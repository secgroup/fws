{-# OPTIONS_GHC -O2 #-}
{-# LANGUAGE BangPatterns #-}
{-# LANGUAGE NamedFieldPuns #-}
{-# LANGUAGE RecordWildCards #-}
{-# LANGUAGE DeriveFunctor #-}
{-# LANGUAGE DeriveTraversable #-}

{-|
Module      : FWS
Description : Main Synthesis functions
Copyright   : (c) 2017 Chiara Bodei <chiara at di.unipi.it>
              (c) 2017 Pierpaolo Degano <degano at di.unipi.it>
              (c) 2017 Riccardo Focardi <focardi at unive.it>
              (c) 2017 Letterio Galletta <galletta at di.unipi.it>
              (c) 2017 Mauro Tempesta <tempesta at unive.it>
              (c) 2017 Lorenzo Veronese <852058 at stud.unive.it>
-}

module FWS (
  -- * Synthesis
    MRule(..)
  , synthesizeFirewall
  , synthesizeDiff
  , synthesizeND
  , policyImplication
  , policyEquivalence
  -- * Firewalls
  , Firewall(..)
  , mkFirewall
  -- * Local Constraints
  , LocalFlag(..)
  ) where

import           Control.Monad
import           Data.Foldable       (toList)
import           Data.Function
import           Data.List
import qualified Data.Map         as M
import           Data.Maybe          (maybe, isJust, isNothing, catMaybes, mapMaybe)
import qualified Data.Set         as S

import Control.Monad.IO.Class (liftIO)
import Control.Exception.Base (assert)

import           Z3.Monad

import           FWS.BVSat
import           FWS.BVPredicates
import           FWS.Utils
import           FWS.Parsers
import           FWS.Types

--------------------------------------------------------------------------------
-- CHAIN PREDICATES

-- | Unfold chain algorithm (removing calls and gotos)
unfoldChain :: Chain -> Chain
unfoldChain ruleset packet = go LTrue (S.singleton formula) formula
  where
    formula = ruleset packet
    go f set chain = case chain of
      []                      -> []
      (phi, Return)   : xs    -> go (And f $ Not phi) set xs
      (phi, Call xs') : xs
        | S.notMember xs' set -> go (And f phi) (S.insert xs' set) xs'
                                 ++ go f set xs
        | otherwise           -> (And f phi, Drop) : go f set xs
      (phi, Goto xs') : xs
        | S.notMember xs' set -> go (And f phi) (S.insert xs' set) xs'
                                 ++ go (And f $ Not phi) set xs
        | otherwise           -> (And f phi, Drop) : go (And f $ Not phi) set xs
      (phi, t)        : xs    -> (And f phi, t) : go f set xs

-- | Make a Formula from a chain, two packets and a default action
predicateOfChain :: Bool -> Chain -> (Packet, Packet) -> BVFormula
predicateOfChain defaccept chain (p, p') = loop $ chain p
  where
    def | defaccept = LTrue
        | otherwise = LFalse
    anyAddr = (Range $ universeBVSort BV32, Range $  universeBVSort BV16)
    loop []                         = And def $ packetEq p p'
    loop ((phi, Accept)        :xs) = Or (And phi $ packetEq p p')
                                         (And (Not phi) $ loop xs)
    loop ((phi, Drop)          :xs) = And (Not phi) $ loop xs
    loop ((phi, Nat dn sn)     :xs) = Or (And phi (inNat p' p
                                                   dn sn RewriteBoth))
                                         (And (Not phi) $ loop xs)
    loop ((phi, CheckState dir):xs) = Or (And phi (inNat p' p
                                                   anyAddr anyAddr dir))
                                         (And (Not phi) $ loop xs)
    -- loop ((phi, Mark m)) = ...
    loop _                          = error "predicateOfChain: Invalid Chain!"

-- | Predicate of dropped packets for a single chain
dropPredicateOfChain :: Bool -> Chain -> Packet -> BVFormula
dropPredicateOfChain defaccept chain p = loop $ chain p
  where
    notDef = if defaccept then LFalse else LTrue -- Not(defaccept)
    loop []                         = notDef
    loop ((phi, Accept)        :xs) = And (Not phi) $ loop xs
    loop ((phi, Drop)          :xs) = Or phi $ And (Not phi) (loop xs)
    loop ((phi, Nat dn sn)     :xs) = And (Not phi) $ loop xs
    loop ((phi, CheckState dir):xs) = And (Not phi) $ loop xs
    -- loop ((phi, Mark m)) = ...
    loop _                          = error "dropPredicateOfChain: Invalid Chain!"

inNat :: Packet -> Packet -> NatRange -> NatRange -> RewriteDir -> BVFormula
inNat (Packet si sp di dp sa da p s) (Packet si' sp' di' dp' sa' da' p' s')
      (dip, dport) (sip, sport) dir = foldl1 And [sim, spm, dim, dpm, sam, dam, pm, sm]
  where dim | dip == Id   || dir == RewriteSrc = Eq di di'
            | otherwise                        = match di dip
        dpm | dport == Id || dir == RewriteSrc = Eq dp dp'
            | otherwise                        = match dp dport
        sim | sip == Id   || dir == RewriteDst = Eq si si'
            | otherwise                        = match si sip
        spm | sport == Id || dir == RewriteDst = Eq sp sp'
            | otherwise                        = match sp sport
        sam                                    = Eq sa sa'
        dam                                    = Eq da da'
        pm                                     = Eq p p'
        sm                                     = Eq s s'
        match e@(Var s _) (Range (I f@(Lit s' _) t@(Lit s'' _)))
          | s /= s' || s' /= s'' || s /= s'' = error "inNat: Invalid Sort"
          | f /= t                           = And (e `Ge` f) (e `Le` t)
          | otherwise                        = Eq e f

--------------------------------------------------------------------------------
-- FIREWALL PREDICATES

-- | Substitute p vars in p' if they are marked with True in the first argument
applySubst :: PPacket Bool -> PPacket a -> PPacket a -> PPacket a
applySubst subst p p' = packetFromList $ zipWith3 (\f a b -> if f then a else b)
  (toList subst) (toList p) (toList p')

-- | Check if the chain has nat
hasNat :: Ruleset -> Bool
hasNat = or . map isNat
  where isNat (_, Nat _ _)      = True
        isNat (_, CheckState _) = True
        isNat _                 = False

type Substitution = PPacket Bool
type ActionPredicate = Chain -> Bool -> Packet -> BVFormula

-- | Get all possible substitutions of a chain
getSubsts :: Ruleset -> [(Substitution, ActionPredicate)]
getSubsts ruleset = filterPacket : (nats ++ checkstates)
  where
    filterPacket = (packetFromList $ replicate 8 True, withoutNat)
    nats         = sorted $ mapMaybe (getnat . snd) ruleset
    checkstates  = sorted $ mapMaybe (getcheckstate . snd) ruleset

    sorted = nubBy ((==) `on` fst) . sortOn (length . filter (==False) . toList . fst)

    getnat n@(Nat (dstIp,dstPort) (srcIp,srcPort)) =
      let srcMac   = Id
          dstMac   = Id
          protocol = Id
          state    = Id
      in Just (fmap (==Id) Packet{..}, withNat $ natType n)
    getnat _ = Nothing

    getcheckstate n@(CheckState RewriteBoth) =
      Just (Packet False False False False True True True True, withCheckstate (==n))
    getcheckstate n@(CheckState RewriteDst) =
      Just (Packet True True False False True True True True, withCheckstate (==n))
    getcheckstate n@(CheckState RewriteSrc) =
      Just (Packet False False True True True True True True, withCheckstate (==n))
    getcheckstate _ = Nothing

-- | Check if two nat are of the same type
natType :: Action -> Action -> Bool
natType n action = natSig n == natSig action
  where natSig (Nat (dip, dp) (sip, sp)) = map (==Id) [dip,dp,sip,dp]

-- | Nat constraint
withNat :: (Action -> Bool) -> ActionPredicate
withNat isNatType chain _ p = loop $ chain p
  where loop [] = LFalse
        loop ((phi, nat@(Nat _ _)):xs) | isNatType nat = phi `Or` loop xs
        loop ((phi, _)            :xs)                 = Not phi `And` loop xs

-- | Filter constraint
withoutNat :: ActionPredicate
withoutNat chain dp p = loop $ chain p
  where loop [] | dp        = LTrue
                | otherwise = LFalse
        loop ((phi, Accept):xs) = phi `Or` loop xs
        loop ((phi, _)     :xs) = Not phi `And` loop xs

-- | CheckState constraint
withCheckstate :: (Action -> Bool) -> ActionPredicate
withCheckstate isCSType chain _ p = loop $ chain p
  where loop [] = LFalse
        loop ((phi, cs@(CheckState _)):xs) | isCSType cs = phi `Or` loop xs
        loop ((phi, _)                :xs)               = Not phi `And` loop xs

-- | Generate all possible predicates (paths and substitutions) for a control diagram
firewallPredicates :: Ord t => Firewall t -> PPacket Term -> GenPacket [BVFormula]
firewallPredicates Firewall{..} packet = go initialState [] packet
  where go st states p
          | st == finalState = return [LTrue]
          | otherwise        = do
              let chain = chains M.! st
              let defPl = defaultPolicies M.! st
              fresh <- if hasNat $ chain p then mkFreshPacket else pure p
              let substs = getSubsts $ chain p
              fmap concat $ forM substs $ \(subst, typePred) -> do
                let newp       = applySubst subst p fresh
                let pred       = predicateOfChain defPl chain (p, newp)
                let tconstr    = typePred chain defPl p
                let constpred  = And tconstr pred
                ns <- forM [ edge | edge@(q,_,q') <- controlDiagram, q == st, not $ q' `elem` states ]
                    $ \(_, phi, st') ->  map (And $ phi newp) <$> go st' (st:states) newp
                return $ concatMap (map (And constpred)) ns

-- | Generic extract function for cubes and multicubes
extractWith :: (MonadZ3 m, Traversable t1, Ord t)
            => ([Term] -> t2 -> PPacket Term -> t3)
            -> (AST -> [AST] -> m (t1 t2))
            -> (t3 -> t3 -> b)
            -> ((PPacket Term, PPacket Term) -> BVFormula)
            -> Firewall t
            -> m [t1 b]
extractWith instantiate allBVSat mkRule query fw@(Firewall{..}) = do
   let (p,frms) = flip runGenPacket 0 $ (,) <$> mkFreshPacket
                                            <*> firewallPredicates fw p
   forM (zip (frms) [1..]) $ \(pred, n) -> do
    let pvars = map fst $ sortOn snd $ M.assocs $ formulaVarsCount pred
    let pout  = getPout p pvars
    let qpred = And (query (p,pout)) pred
    (frm, vm) <- z3Predicate qpred $ Just pvars

    printProgress n (length frms)
    debug $ "+ Subst:"

    cubes <- allBVSat frm $ map (vm M.!) pvars
    forM cubes $ \c -> do
      return $ mkRule (instantiate pvars c p) (instantiate pvars c pout)

-- | Generate the predicate of dropped packets for the given firewall
dropPredicate :: Ord t => Firewall t -> Packet -> GenPacket BVFormula
dropPredicate Firewall{..} pin = go initialState [] pin
  where go st states p
          | st == finalState = return LFalse
          | otherwise        = do
              fresh     <- mkFreshPacket
              let chain = chains M.! st
              let defPl = defaultPolicies M.! st
              let drop  = dropPredicateOfChain defPl chain p
              let pred  = predicateOfChain defPl chain (p, fresh)
              branches  <- forM [ edge | edge@(q,_,q') <- controlDiagram, q == st, not $ q' `elem` states ]
                         $ \(_, phi, st') -> And (phi fresh) <$> go st' (st:states) fresh
              return $ Or drop $ Exists (toList fresh) (And pred $ foldl1 Or branches)

-- | Generate a list of drop predicates
dropPredicates :: Ord t => Firewall t -> Packet -> GenPacket [BVFormula]
dropPredicates Firewall{..} pin = go initialState [] pin
   where go st states p
          | st == finalState = return [LFalse]
          | otherwise        = do
              let chain = chains M.! st
              let defPl = defaultPolicies M.! st
              let drop  = dropPredicateOfChain defPl chain p
              fresh <- if hasNat $ chain p then mkFreshPacket else pure p
              let substs = getSubsts $ chain p
              fmap concat $ forM substs $ \(subst, typePred) -> do
                let newp  = applySubst subst p fresh
                let pred  = predicateOfChain defPl chain (p, newp)
                let tpred = typePred chain defPl p
                let constp = And tpred pred

                ns <- forM [ edge | edge@(q,_,q') <- controlDiagram, q == st,
                             not $ q' `elem` states ]
                    $ \(_, phi, st') ->  map (And $ phi newp) <$> go st' (st:states) newp

                return $ concatMap (map (\x -> Or drop (And constp x))) ns


-- | Extract non-deterministically dropped packets from a firewall
synthesizeND :: Ord t => [Integer] -> LocalFlag -> LocalFlag -> String -> Firewall t -> IO [MRule]
synthesizeND locals locsrc locdst queryStr fw = do
  let (p, formulas, drops) = flip runGenPacket 0 $ (,,)
                   <$> mkFreshPacket
                   <*> firewallPredicates fw p
                   <*> dropPredicates fw p

  evalZ3Model $ concat <$> (forM (zip3 formulas drops [1..]) $ \(pred, drop, n) -> do
    let pvars = map fst $ sortOn snd $ M.assocs $ formulaVarsCount pred
    let dvars = map fst $ sortOn snd $ M.assocs $ formulaVarsCount drop
    let vvars = map fst $ sortOn snd $ M.assocs $ formulaVarsCount (And pred drop)

    let pout  = getPout p pvars -- accepted packet
    let dout  = getPout p dvars -- dropped packet

    let qpred = And (query (p,pout)) pred
    (frm, vm) <- z3Predicate (And qpred drop) $ Just vvars

    printProgress n (length formulas)
    debug $ "+ Subst:"

    cubes <- allBVSat' frm $ map (vm M.!) vvars
    forM cubes $ \c -> do
      return $ mkMRule (instantiate vvars c p) (instantiate vvars c dout))
  where
    query = mkLocalsQuery queryStr locals locsrc locdst

-- | Extract non-deterministically dropped packets from a firewall (with existentials)
synthesizeND' :: Ord t => [Integer] -> LocalFlag -> LocalFlag -> String -> Firewall t -> IO [MRule]
synthesizeND' locals locsrc locdst queryStr fw = do
  let (p, formulas, drop) = flip runGenPacket 0 $ (,,)
                              <$> mkFreshPacket
                              <*> firewallPredicates fw p
                              <*> dropPredicate fw p
  evalZ3Model $ concat <$> (forM (zip formulas [1..]) $ \(pred, n) -> do
    let pvars = map fst $ sortOn snd $ M.assocs $ formulaVarsCount pred
    let pvars' = map fst $ sortOn snd $ M.assocs $ formulaVarsCount (And pred drop)
    let pout  = getPout p pvars
    let qpred = And (query (p,pout)) pred
    (frm, vm) <- z3Predicate (And qpred drop) $ Just pvars' -- pred_i /\ \mathcal{D}

    printProgress n (length formulas)
    debug $ "+ Subst:"

    -- synthesize over variables of predicate and only p_in of drop predicate
    cubes <- allBVSat' frm $ map (vm M.!) pvars
    forM cubes $ \c -> do
      return $ mkMRule (instantiate pvars c p) (instantiate pvars c pout))
  where
    query = mkLocalsQuery queryStr locals locsrc locdst

-- | Make the output packet from a list of variables and the input packet:
--   Take all the variables with the maximum index
getPout :: Packet -> [Term] -> Packet
getPout pin vars = fmap ff pin
  where ff (Var s n) = let basename = takeWhile (not.(=='_')) n in
          Var s $ foldl max n $ filter (isPrefixOf basename) $ map (\(Var _ n) -> n) vars

-- | Extract MRules from firewall
synthesizeFirewall :: Ord t => [Integer] -> LocalFlag -> LocalFlag -> String -> Firewall t -> IO [MRule]
synthesizeFirewall locals locsrc locdst queryStr fw = evalZ3Model$
  concat <$> extractWith instantiate allBVSat' mkMRule query fw
  where query = mkLocalsQuery queryStr locals locsrc locdst

-- | Make a query to constrain source and destination addresses to be (or not to be) a local address
mkLocalsQuery :: String -> [Integer] -> LocalFlag -> LocalFlag -> ((Packet, Packet) -> BVFormula)
mkLocalsQuery queryStr locals locsrc locdst (p,p') =
  foldl1 And [inputQuery (p, p'), localSrcQuery p, localDstQuery p']
  where
    isLocal var = foldr1 Or $ map (Eq var . Lit BV32) locals

    inputQuery                                   = parseFormula' queryStr
    localSrcQuery Packet{..} | locsrc == Local   = isLocal srcIp
                             | locsrc == NoLocal = Not $ isLocal srcIp
                             | otherwise         = LTrue
    localDstQuery Packet{..} | locdst == Local   = isLocal dstIp
                             | locdst == NoLocal = Not $ isLocal dstIp
                             | otherwise         = LTrue

--------------------------------------------------------------------------------
-- POLICY ANALYSIS

-- | Generate a firewall predicate
predicateOfFirewall :: Ord t => Firewall t -> (Packet, Packet) -> GenPacket BVFormula
predicateOfFirewall Firewall{..} (pin,pout) = go initialState [] pin
  where go st states p
          | st == finalState = return $ packetEq p pout
          | otherwise        = do
              fresh     <- mkFreshPacket
              let chain = chains M.! st
              let defPl = defaultPolicies M.! st
              let pred  = predicateOfChain defPl chain (p, fresh)
              branches  <- forM [ edge | edge@(q,_,q') <- controlDiagram, q == st, not $ q' `elem` states ]
                         $ \(_, phi, st') -> And (phi fresh) <$> go st' (st:states) fresh
              return $ Exists (toList fresh) $ And pred $ foldl1 Or branches

-- | Generate the same predicate as `predicateOfFirewall` but using the list of predicates
--   `firewallPredicates` instead of generating a new one
predicateOfFirewall' :: Ord t => Firewall t -> (Packet, Packet) -> GenPacket BVFormula
predicateOfFirewall' fw@(Firewall{..}) (pin,pout) = do
  preds <- firewallPredicates fw pin
  predsVars <- forM preds $ \p -> do
    let pvars = formulaVars p
    let pout' = getPout pin $ toList pvars
    return $ (And p (packetEq pout' pout), pvars)
  let predsOut  = map fst predsVars
  let vars      = toList $ foldl S.union S.empty $ map snd predsVars
  let existVars = [ x | x <- vars , not $ x `elem` (toList pin ++ toList pout) ]
  return $ Exists existVars $ foldl1 Or predsOut

-- | Check for policy implication
policyImplication :: (MonadZ3 z3, Ord t) => Firewall t -> Firewall t
                  -> String -> [Integer] ->  LocalFlag -> LocalFlag -> z3 Bool
policyImplication fw fw' queryStr locals locsrc locdst = do
  solver          <- mkSolver
  let implication = Not pred `And` pred'
  implies         <- simplify . fst =<< z3Predicate implication Nothing
  solverAssert solver implies
  res <- solverCheck solver
  return $ res == Unsat
  where
    pin   = mkPacket 0
    pout  = mkPacket 1
    pred  = And query $ flip runGenPacket 2 $ predicateOfFirewall' fw  (pin, pout)
    pred' = And query $ flip runGenPacket 2 $ predicateOfFirewall' fw' (pin, pout)
    query = mkLocalsQuery queryStr locals locsrc locdst (pin, pout)

-- | Check for policy equivalence
policyEquivalence :: (MonadZ3 z3, Ord t) => Firewall t -> Firewall t
                  -> String -> [Integer] ->  LocalFlag -> LocalFlag -> z3 Bool
policyEquivalence fw fw' queryStr locals locsrc locdst = do
  right <- policyImplication fw  fw' queryStr locals locsrc locdst
  left  <- policyImplication fw' fw queryStr locals locsrc locdst
  return $ left && right

-- | Synthesize the difference between two firewalls
synthesizeDiff :: Ord t => Firewall t -> Firewall t -> String
               -> [Integer] ->  LocalFlag -> LocalFlag -> IO ([MRule], [MRule])
synthesizeDiff fw fw' queryStr locals locsrc locdst = evalZ3Model$ do
  rules  <- concat <$> extract fw
  rules' <- concat <$> extract fw'
  let plusDiff  = getDiffs rules' rules
  let minusDiff = getDiffs rules rules'
  return (plusDiff, minusDiff)
  where
    query = mkLocalsQuery queryStr locals locsrc locdst
    extract = extractWith instantiate allBVSat' mkMRule query
    getDiffs a b = mapMaybe (getIfNotIn b) a
    getIfNotIn b a | any (equivalent a) b = Nothing
                   | otherwise            = Just a

    equivalent (MRule pin pout) (MRule pin' pout') =
      map (fmap sort) (toList pin) == map (fmap sort) (toList pin')
      && map (fmap sort) (toList pout) == map (fmap sort) (toList pout')

--------------------------------------------------------------------------------
-- FIREWALLS

-- | Make a firewall from chain and diagram files
mkFirewallFromFiles :: FilePath -> FilePath -> [Integer] -> IO (Firewall String)
mkFirewallFromFiles diagramFile chainFile localAddresses = do
  diagramContent                  <- readFile diagramFile
  chainsContent                   <- readFile chainFile
  return $ mkFirewall diagramFile diagramContent chainFile chainsContent localAddresses

-- | Make a firewall from chain and diagram
mkFirewall :: String -> String -> String -> String -> [Integer] -> Firewall String
mkFirewall diagramFile diagram chainFile chain localAddresses =
  let (init, final, nodes, edges) = parseControlDiagram locals diagramFile diagram
      chains                      = parseChains chainFile chain
      chainMap                    = mkChainsMap nodes chains
  in Firewall { controlDiagram  = edges
              , initialState    = init
              , finalState      = final
              , defaultPolicies = fmap fst chainMap
              , chains          = fmap (unfoldChain . snd) chainMap
              }
  where locals = map (Lit BV32) localAddresses
        defined name = find (\(NamedChain n _ _) -> n == name)
        mkChainsMap nodes chains =  M.fromList
          [ (node, (def, chain))
          | node <- nodes
          , let (def, chain) = maybe (True, (\_ -> [])) (\(NamedChain _ d c) -> (d,c))
                  $ defined node chains
          ]
