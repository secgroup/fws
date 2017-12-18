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

Packets, Chains, Multi-Cube Extraction, Firewalls
-}

module FWS where

import           Control.Monad
import           Control.Monad.State hiding (state)
import           Data.Char                  (isLower, isSpace)
import           Data.Foldable              (toList)
import           Data.Function
import           Data.List
import qualified Data.Map            as     M
import           Data.Maybe                 (maybe, isJust, isNothing, catMaybes, mapMaybe)
import           Data.Monoid
import           Text.Printf                (printf)
import           Text.Parsec         hiding (State)
import qualified Data.Set            as     S
import           Debug.Trace                (trace, traceM)
import           System.Environment         (getArgs)
import           System.Exit                (die)
import           System.IO                  (hPutStr, stderr)

import           Text.Layout.Table
import           Text.Layout.Table.Internal (rows)
import           Z3.Monad

import           FWS.BVSat
import           FWS.BVPredicates
import           FWS.Utils


--------------------------------------------------------------------------------
-- PACKETS

-- | Parametrized packet type
data PPacket a = Packet { srcIp    :: !a
                        , srcPort  :: !a
                        , dstIp    :: !a
                        , dstPort  :: !a
                        , protocol :: !a
                        , state    :: !a
                        } deriving (Show, Eq, Ord, Functor, Foldable, Traversable)

-- | Packet of terms
type Packet = PPacket Term

-- | Packet of list of intervals of bitvectors
type IMPacket = PPacket (Maybe [Interval BV])

-- | Formula to check if two term lists are equal
listEq :: [Term] -> [Term] -> BVFormula
listEq l = foldl1 And . zipWith Eq l

-- | Formula to check if two packet are equal
packetEq :: Packet -> Packet -> BVFormula
packetEq p p' = listEq (toList p) (toList p')

-- | Make a packet with new variables
mkPacket :: Int -> Packet
mkPacket n = Packet {srcIp, srcPort, dstIp, dstPort, protocol, state}
  where srcIp    = Var BV32 $ "srcIp_"    ++ show n
        srcPort  = Var BV16 $ "srcPort_"  ++ show n
        dstIp    = Var BV32 $ "dstIp_"    ++ show n
        dstPort  = Var BV16 $ "dstPort_"  ++ show n
        protocol = Var BV8  $ "protocol_" ++ show n
        state    = Var BV1  $ "state_"    ++ show n

-- | Create a Packet from a list
packetFromList :: [a] -> PPacket a
packetFromList [srcIp, srcPort, dstIp, dstPort, protocol, state] = Packet{..}
packetFromList _ = error "packetFromList: Invalid List"

-- | Zip two packets with a function
zipPacketsWith :: (a -> b -> c) -> PPacket a -> PPacket b -> PPacket c
zipPacketsWith f a b = packetFromList $ zipWith f (toList a) (toList b)

--------------------------------------------------------------------------------
-- CHAINS

-- | Nat rewrite direction
data RewriteDir = RewriteDst | RewriteSrc | RewriteBoth deriving (Show, Eq, Ord)

-- | Firewall chain type
type Chain = Packet -> Ruleset
type Ruleset = [(BVFormula, Action)]

-- | Nat IP, Port ranges
type NatRange = (Range, Range)
data Range = Id | Range (Interval Term) deriving (Show, Eq, Ord)

-- | Rule actions
data Action = Accept
            | Drop
            | Call Ruleset
            | Goto Ruleset
            | Return
            | Nat NatRange NatRange
            | CheckState RewriteDir
            deriving(Show, Eq, Ord)

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
    loop _                          = error "predicateOfChain: Invalid Chain!"

inNat :: Packet -> Packet -> NatRange -> NatRange -> RewriteDir -> BVFormula
inNat (Packet si sp di dp p s) (Packet si' sp' di' dp' p' s')
      (dip, dport) (sip, sport) dir = foldl1 And [sim, spm, dim, dpm, pm, sm]
  where dim | dip == Id   || dir == RewriteSrc = Eq di di'
            | otherwise                        = match di dip
        dpm | dport == Id || dir == RewriteSrc = Eq dp dp'
            | otherwise                        = match dp dport
        sim | sip == Id   || dir == RewriteDst = Eq si si'
            | otherwise                        = match si sip
        spm | sport == Id || dir == RewriteDst = Eq sp sp'
            | otherwise                        = match sp sport
        pm                                     = Eq p p'
        sm                                     = Eq s s'
        match e@(Var s _) (Range (I f@(Lit s' _) t@(Lit s'' _)))
          | s /= s' || s' /= s'' || s /= s'' = error "inNat: Invalid Sort"
          | f /= t                           = And (e `Ge` f) (e `Le` t)
          | otherwise                        = Eq e f

--------------------------------------------------------------------------------
-- CHAINS PARSER

-- | Ruleset Action Before the connection of the calls and gotos
data ParseAction = Action Action | Call_ String | Goto_ String
                 deriving (Show, Eq, Ord)

-- | Ruleset before the connection of calls and gotos
type ParseRuleset = [(BVFormula, ParseAction)]

-- | Chain with name and default action
data NamedChain a = NamedChain String Bool !a
                  deriving (Eq, Functor, Foldable, Traversable)

-- | Parse Chain file and connect all calls and gotos
parseChains :: FilePath -> String -> [NamedChain Chain]
parseChains filename str = case parse chainDefs filename str of
  Left  !e -> error $ show e
  Right v -> map (fmap connectCalls) v
    where
      chainMap = M.fromList [(name, chain) | NamedChain name _ chain <- v]

      connectCalls pchain p = map (lookupAndConnect p) $ pchain p

      lookupAndConnect p (phi, Call_ str) = (phi, Call $ connectCalls (chainMap M.! str) p)
      lookupAndConnect p (phi, Goto_ str) = (phi, Goto $ connectCalls (chainMap M.! str) p)
      lookupAndConnect p (phi, Action a)  = (phi, a)

-- | Parse Formula
parseFormula :: String -> (Packet -> BVFormula)
parseFormula str = case parse (formula pvariable) "" str of
  Left !e -> error $ show e
  Right v -> v

-- | Parse Formula with p' variables
parseFormula' :: String -> ((Packet, Packet) -> BVFormula)
parseFormula' str = case parse (formula ppvariable) "" str of
  Left !e -> error $ show e
  Right v -> v

-- | Chain definitions
chainDefs :: Parsec String () [NamedChain (Packet -> ParseRuleset)]
chainDefs = many1 $ do (name, def) <- chainDefinition
                       ruleset <- chain
                       return $ NamedChain name def ruleset

-- | Chain header with name and default policy
chainDefinition :: Parsec String () (String, Bool)
chainDefinition = (,) <$> (symbol "CHAIN" *> identifier)
                      <*> option False (False <$ symbol "DROP" <|> True <$ symbol "ACCEPT")
                      <*  symbol ":"

-- | Chain as list of formula, action pairs
chain :: Parsec String () (Packet -> ParseRuleset)
chain = do xs <- many1 $ pair (formula pvariable) action
           return $ \p -> map (\(f, a) -> (f p, a)) xs

-- | Match p between parenthesis
parens :: Parsec String () a -> Parsec String () a
parens p = between (symbol "(") (symbol ")") p

-- | Math a pair of a and b
pair :: Parsec String () a -> Parsec String () b -> Parsec String () (a,b)
pair a b = parens $ (,) <$> a <*> (symbol "," *> b)

-- | Action Parser that returns a ParseActions (Calls and Gotos with strings)
action :: Parsec String () ParseAction
action =  Action Accept <$ symbol "ACCEPT" <|> Action Drop <$ symbol "DROP"
      <|> Action <$> (CheckState <$> (symbol "CHECK-STATE" *> parens dir))
      <|> Action <$> (uncurry Nat <$> (symbol "NAT" *> pair natrange natrange))
      <|> Action <$> (Return <$ symbol "RETURN")
      <|> Call_ <$> (symbol "CALL" *> parens identifier)
      <|> Goto_ <$> (symbol "GOTO" *> parens identifier)
      where
        dir = RewriteBoth <$ symbol "<->" <|> RewriteDst <$ symbol "->"
           <|> RewriteSrc <$ symbol "<-"

-- | NAT Range with address, ':' and port ranges
natrange :: Parsec String () NatRange
natrange = do
  addr <- option Id $ id <|> Range <$> (fmap (Lit BV32) <$> ip)
  port <- option Id $ char ':' *> (id <|> Range <$> (fmap (Lit BV16) <$> range))
  return $ (addr, port)
  where id = Id <$ string "Id"

-- | Range with "*" and "-"
range :: Parsec String () (Interval Integer)
range =  (I 0 0) <$ symbol "NEW"
     <|> (I 1 1) <$ symbol "ESTABLISHED"
     <|> (I 0 $ 2^16-1) <$ symbol "*"
     <|> try (I <$> natural <*> (char '-' *> natural))
     <|> singleton <$> natural

-- | Matches the str symbol without whitespace whitespace
symbol :: String -> Parsec String () String
symbol str = try (junk *> string str <* junk)

-- | Whitespace
junk :: Parsec String () ()
junk = void $ many (space <|> newline)

-- | Packet Variable
pvariable :: Parsec String () (Packet -> Term)
pvariable =  srcIp <$ symbol "srcIp" <|> srcPort <$ symbol "srcPort"
         <|> dstIp <$ symbol "dstIp" <|> dstPort <$ symbol "dstPort"
         <|> state <$ symbol "state" <|> protocol <$ symbol "protocol"

ppvariable :: Parsec String () ((Packet, Packet) -> Term)
ppvariable =  try ( (srcIp . snd) <$ symbol "srcIp'" ) <|> try ( (srcPort  . snd) <$ symbol "srcPort'" )
          <|> try ( (dstIp . snd) <$ symbol "dstIp'" ) <|> try ( (dstPort  . snd) <$ symbol "dstPort'" )
          <|> try ( (state . fst) <$ symbol "state"  ) <|> try ( (protocol . fst) <$ symbol "protocol" )
          <|> try ( (srcIp . fst) <$ symbol "srcIp"  ) <|> try ( (srcPort  . fst) <$ symbol "srcPort"  )
          <|> try ( (dstIp . fst) <$ symbol "dstIp"  ) <|> try ( (dstPort  . fst) <$ symbol "dstPort"  )

-- | Matches a Formula with &&, || and not
formula :: Parsec String () (a -> Term) ->  Parsec String () (a -> BVFormula)
formula variable = try double <|> try single <|> try parentesized <|> term variable
  where unOperator = Not <$ symbol "not"
        binOperator = And <$ symbol "&&" <|> Or <$ symbol "||"
        parentesized = parens $ formula variable
        single = do op <- unOperator
                    f1 <- parentesized
                    return $ \p -> op (f1 p)
        double = do f1 <- parentesized <|> single <|> term variable
                    op <- binOperator
                    f2 <- formula variable
                    return $ \p -> op (f1 p) (f2 p)

-- | Matches a single term that can be "var =~ addr" or "var == value"
term :: Parsec String () (a -> Term) -> Parsec String () (a -> BVFormula)
term variable = (\p -> LTrue) <$ symbol "true"
     <|> do
  var <- variable
  symbol "=="
  star <|> try (addr var) <|> number var
  where star       = (\p -> LTrue) <$ char '*'
        addr var   = do addr <- ip
                        return $ \p -> matchIPInterval (var p) addr
        number var = do port <- (singleton <$> proto) <|> range
                        return $ \p -> matchGeneric (var p) port

-- | Valid identifier with alphanumeric, "-" and "_"
identifier :: Parsec String () String
identifier = many1 (alphaNum <|> char '-' <|> char '_' <|> char '.')


--------------------------------------------------------------------------------
-- TABLES

data LocalFlag = Local | NoLocal | Both deriving (Show, Eq)

data NatFlag   = ShowNat | ShowFilter | ShowAll deriving (Show, Eq)

-- | Instantiate a packet from a multicube and its variables
instantiate :: (Functor f, Eq a)
                 => [a] -> Multicube -> f a -> f (Maybe [Interval BV])
instantiate vars mcb = fmap (flip lookup $ zip vars $ multicubeList mcb)

-- | Multicubes rule
data MRule = MRule !IMPacket !IMPacket deriving (Eq)

instance Show MRule where
  show = mruleTable asciiTable ShowNat . pure . mruleToRowG ShowNat [] False False

-- | Make a MRule from a pair of IMPacket
mkMRule :: IMPacket -> IMPacket -> MRule
mkMRule pin pout = MRule pin (without pin pout)
  where without p = zipPacketsWith (\i o -> if i == o then Nothing else o) p

type TableConstructor = [String] -> [RowGroup] -> String

-- | Make a rowG from a MRule
mruleToRowG :: NatFlag -> [Integer] -> Bool -> Bool -> MRule -> RowGroup
mruleToRowG = prefixMruleToRowG []

-- | Make a rowG with + or - in front from a MRule
mruleDiffToRowG :: Bool -> NatFlag -> [Integer] -> Bool -> Bool -> MRule -> RowGroup
mruleDiffToRowG addp = prefixMruleToRowG [[if addp then "+" else "-"]]

-- | Make a rowG from a MRule with additional columns in front
prefixMruleToRowG :: [[String]] -> NatFlag -> [Integer] -> Bool -> Bool -> MRule -> RowGroup
prefixMruleToRowG prefix natFlag locals hideSrc hideDst (MRule pin pout) =
  colsAllG top $
  prefix ++
  [ get srcIp "*" (showInverse hideSrc showIPRange) pin     -- srcIps
  , get srcPort "*" (showInverse False showPortRange) pin   -- srcPorts
  ] ++ natTable ++
  [ get dstIp "*" (showInverse hideDst showIPRange) pin     -- DestIp
  , get dstPort "*" (showInverse False showPortRange) pin   -- DestPorts
  , get protocol "*" (showInverse False showProtoRange) pin -- Protos
  , get state "*" (map showNewEstablished) pin              -- States
  ]
  where
    natTable | natFlag == ShowFilter = []
             | otherwise = [ get srcIp "-" (showInverse hideSrc showIPRange) pout    -- SNATIps
                           , get srcPort "-" (showInverse False showPortRange) pout  -- SNATPorts
                           , get dstIp "-" (showInverse hideDst showIPRange) pout    -- DNATIps
                           , get dstPort "-" (showInverse False showPortRange) pout  -- DNATPorts
                           ]

    get field def show = maybe [def] (show . map (fmap (\(BV _ v) -> v))) . field
    showInverse hide show lst
      | isNothing reversed = map show $ sorted lst
      | null rest          = [show all]
      | length rest == 1   = [show all ++ " \\ {" ++ show (head rest) ++ "}"]
      | otherwise          = [show all ++ " \\ {"] ++ map (("  "++).show) (sorted rest) ++ ["}"]
      where reversed          = reverseInterval lst
            Just (all, rest') = reversed
            rest | hide       = filter (\(I a b) -> if a /= b then True else not (a`elem`locals)) rest'
                 | otherwise  = rest'
            sorted            = sortOn imin

-- | make a table to display diffs
mruleDiffTable :: TableConstructor -> NatFlag -> [RowGroup] -> String
mruleDiffTable = prefixMruleTable [ "+/-" ]

-- | Make a table to display mrules
mruleTable :: TableConstructor -> NatFlag -> [RowGroup] -> String
mruleTable = prefixMruleTable []

-- | Make a table with additional columns in front
prefixMruleTable :: [String] -> TableConstructor -> NatFlag -> [RowGroup] -> String
prefixMruleTable prefix mkTable ShowFilter =
  mkTable $ prefix ++ [ "Source IP", "Source Port", "Destination IP", "Destination Port", "Protocol", "State"]
prefixMruleTable prefix mkTable _          =
  mkTable $ prefix ++ [ "Source IP", "Source Port", "SNAT IP", "SNAT Port", "DNAT IP"
                      , "DNAT Port", "Destination IP", "Destination Port", "Protocol", "State"]


unicodeTable, asciiTable :: [String] -> [RowGroup] -> String
(unicodeTable, asciiTable) = (mkTable unicodeRoundS, mkTable asciiS)
  where mkTable style titles = tableString (map (const def) titles) style (titlesH titles)

texTable :: [String] -> [RowGroup] -> String
texTable titles rowGroups = unlines $
  [ "\\begin{tabular}{ |"++ (intercalate "" $ replicate (length titles) "l|") ++" }"
  , "\\hline"
  , (intercalate " & " $ map (printf "\\textbf{%s}") titles) ++ " \\\\"
  , "\\hline"
  ]
  ++ (map printRow $ map rows rowGroups) ++
  [ "\\end{tabular}" ]
  where
    printRow :: [[String]] -> String
    printRow group = (intercalate "\\\\" $ map (intercalate " & " . map mkverb) group) ++ "\\\\ \\hline"
    mkverb ""        = ""
    mkverb s         = "\\verb|"++s++"|"

-- | show state
showNewEstablished :: (Num a, Eq a) => Interval a -> [Char]
showNewEstablished (I s s1)
  | s==s1 = if s == 0 then "NEW" else "ESTABLISHED"
  | otherwise = "*"

-- | Reverse list of intervals if the result is more readable
--   (less and smaller intervals)
reverseInterval :: [Interval Integer] -> Maybe (Interval Integer, [Interval Integer])
reverseInterval [_] = Nothing
reverseInterval ints
  | range ints > range gaps && length ints > length gaps = Just (I min_ max_, gaps)
  | otherwise = Nothing
  where
    min_ = minimum $ map imin ints
    max_ = maximum $ map imax ints
    gaps = loop $ sortOn imin ints
    range ints = maximum $ map (\(I a b) -> b - a) ints

    loop [] = []
    loop [x] = []
    loop ((I a b):s@(I c d):xs) = (I (b+1) (c-1)) : loop (s:xs)

--------------------------------------------------------------------------------
-- FIREWALL CUBES

type Predicate = Packet -> BVFormula
type Edge chaintype = (chaintype, Predicate, chaintype)

-- | Firewall as control diagram (list of edges), chains
--   and initial and final states
data Firewall chaintype = Firewall { controlDiagram  :: [Edge chaintype]
                                   , chains          :: M.Map chaintype Chain
                                   , defaultPolicies :: M.Map chaintype Bool
                                   , initialState    :: chaintype
                                   , finalState      :: chaintype
                                   }

-- | Unique Packets Monad
type GenPacket a = State Int a

-- | Make a new unique Packet
mkFreshPacket :: GenPacket Packet
mkFreshPacket = do n <- get
                   modify (+1)
                   return $ mkPacket n

-- | Run the GenPacket Monad
runGenPacket ::  GenPacket a -> Int -> a
runGenPacket = evalState

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
    filterPacket = (packetFromList $ replicate 6 True, withoutNat)
    nats         = sorted $ mapMaybe (getnat . snd) ruleset
    checkstates  = sorted $ mapMaybe (getcheckstate . snd) ruleset

    sorted = nubBy ((==) `on` fst) . sortOn (length . filter (==False) . toList . fst)

    getnat n@(Nat (dstIp,dstPort) (srcIp,srcPort)) =
      let protocol = Id
          state    = Id
      in Just (fmap (==Id) Packet{..}, withNat $ natType n)
    getnat _ = Nothing

    getcheckstate n@(CheckState RewriteBoth) =
      Just (Packet False False False False True True, withCheckstate (==n))
    getcheckstate n@(CheckState RewriteDst) =
      Just (Packet True True False False True True, withCheckstate (==n))
    getcheckstate n@(CheckState RewriteSrc) =
      Just (Packet False False True True True True, withCheckstate (==n))
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
extractWith :: (MonadZ3 m, Traversable t1, Show b, Ord t)
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

-- | Display synthesis as a table
printTables :: [Integer] -> TableConstructor -> LocalFlag -> LocalFlag -> NatFlag -> [MRule] -> IO ()
printTables locals mkTable locsrc locdst nat rules = do
  let filters = filter (\(MRule p p') -> all (isNothing) (toList p')) rules
  let nats    = filter (\(MRule p p') -> any (isJust) (toList p')) rules

  when (nat `elem` [ShowAll, ShowFilter] && not (null filters)) $ displayTable ShowFilter filters
  when (nat `elem` [ShowAll, ShowNat]    && not (null nats))    $ displayTable ShowAll nats

  where
    displayTable nat rules = liftIO $ putStrLn $ mruleTable mkTable nat
      $ map (mruleToRowG nat locals (locsrc == NoLocal) (locdst == NoLocal)) rules

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

-- | Display difference table
printDiffTable :: TableConstructor -> String -> String -> [MRule] -> [MRule]
               -> [Integer] ->  LocalFlag -> LocalFlag -> IO ()
printDiffTable mkTable fname fname' plusDiff minusDiff locals locsrc locdst = do
  when (not (null plusDiff) || not (null minusDiff)) $ do
    liftIO $ putStrLn $ "+++ " ++ fname'
    liftIO $ putStrLn $ "--- " ++ fname

  let filters = (map ((,) True) $ getFilters plusDiff) ++ (map ((,) False) $ getFilters minusDiff)
  let nats    = (map ((,) True) $ getNats plusDiff) ++ (map ((,) False) $ getNats minusDiff)

  when (not $ null filters) $ displayTable ShowFilter filters
  when (not $ null nats) $ displayTable ShowAll nats
  where
    displayTable nat rules = liftIO $ putStrLn $ mruleDiffTable mkTable nat
      $ map (\(addp, r) -> mruleDiffToRowG addp nat locals (locsrc == NoLocal) (locdst == NoLocal) r) rules

    getFilters = filter (\(MRule p p') -> all (isNothing) (toList p'))
    getNats    = filter (\(MRule p p') -> any (isJust) (toList p'))

--------------------------------------------------------------------------------
-- Control Diagram Parser

triple :: Parsec String () a -> Parsec String () b -> Parsec String () c
       -> Parsec String () (a,b,c)
triple a b c = parens $ (,,) <$> a <*> (symbol "," *> b) <*> (symbol "," *> c)

listOf :: Parsec String () a -> Parsec String () [a]
listOf p = between (symbol "[") (symbol "]") $ sepBy p (symbol ",")

assignment :: Parsec String () a -> Parsec String () b -> Parsec String () (a, b)
assignment s p = (,) <$> s <*> (symbol "=" *> p)

formulaOrKeyword :: [Term] -> Parsec String () (Packet -> BVFormula)
formulaOrKeyword localAddresses =  try (localSrcParser)
                               <|> try (localDstParser)
                               <|> try (negate <$> (symbol "not" *> localSrcParser))
                               <|> try (negate <$> (symbol "not" *> localDstParser))
                               <|> formula pvariable
  where localSrcParser = localSrc <$ try (symbol "localSrc")
        localDstParser = localDst <$ try (symbol "localDst")
        localSrc (Packet{srcIp}) = foldl1 Or $ map (Eq srcIp) nonEmptyLocals
        localDst (Packet{dstIp}) = foldl1 Or $ map (Eq dstIp) nonEmptyLocals
        negate frm p = Not $ frm p
        nonEmptyLocals | null localAddresses = error "Error: no local address specified"
                       | otherwise           = localAddresses

edges :: [Term] -> Parsec String () [Edge String]
edges locals = listOf $ triple identifier (formulaOrKeyword locals) identifier

controlDiagramSpec :: [Term] -> Parsec String () (String, String, [String], [Edge String])
controlDiagramSpec locals = do
  symbol "CONTROL DIAGRAM:"
  nodes    <- snd <$> assignment (symbol "nodes") (listOf identifier)
  edgeList <- snd <$> assignment (symbol "edges") (edges locals)
  initial  <- snd <$> assignment (symbol "initial") identifier
  final    <- snd <$> assignment (symbol "final") identifier
  return (initial, final, nodes, edgeList)

parseControlDiagram :: [Term] -> FilePath -> String -> (String, String, [String], [Edge String])
parseControlDiagram locals path file = case parse (controlDiagramSpec locals) path file of
  Left !e -> error $ show e
  Right v -> v

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
