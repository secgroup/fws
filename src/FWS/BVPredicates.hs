
{-|
Module      : BVPredicates
Description : Predicates over bitvectors
Copyright   : (c) 2017 Chiara Bodei <chiara at di.unipi.it>
              (c) 2017 Pierpaolo Degano <degano at di.unipi.it>
              (c) 2017 Riccardo Focardi <focardi at unive.it>
              (c) 2017 Letterio Galletta <galletta at di.unipi.it>
              (c) 2017 Mauro Tempesta <tempesta at unive.it>
              (c) 2017 Lorenzo Veronese <852058 at stud.unive.it>
-}

module FWS.BVPredicates where

import           Control.Monad
import qualified Data.Map            as M
import           Data.Monoid
import qualified Data.Set            as S
import           Z3.Monad
import           FWS.Utils

--------------------------------------------------------------------------------
-- TYPES

-- | Formula over bitvectors
data BVFormula = Lt !Term !Term
               | Gt !Term !Term
               | Le !Term !Term
               | Ge !Term !Term
               | Eq !Term !Term
               | Ne !Term !Term
               | And !BVFormula !BVFormula
               | Or  !BVFormula !BVFormula
               | Not !BVFormula
               | LTrue
               | LFalse
               | Exists ![Term] !BVFormula
               | Forall ![Term] !BVFormula
               deriving (Show, Eq, Ord)

-- | Accepted sorts for bitvectors
data BVSort = BV48
            | BV32
            | BV16
            | BV8
            | BV1
            deriving (Show, Eq, Ord)

-- | Term as a variable or literal value
data Term = Lit BVSort Integer
          | Var BVSort String
          deriving (Show, Eq, Ord)

--------------------------------------------------------------------------------
-- Ruleset Predicates

-- | Predicate to match the given IP adress range as string
matchIP :: Term -> String -> BVFormula
matchIP term addr = matchIPInterval term $ parseIP addr

-- | Predicate to match the given IP range
matchIPInterval :: Term -> Interval Integer -> BVFormula
matchIPInterval ip@(Var BV32 _) int = matchGeneric ip int
matchIPInterval _ _ = error "matchIPInterval: Invalid Term"

matchMACInterval :: Term -> Interval Integer -> BVFormula
matchMACInterval mac@(Var BV48 _) int = matchGeneric mac int
matchMACInterval _ _ = error "matchMACInterval: Invalid Term"

-- | Predicate to match the given Port range
matchPort :: Term -> Interval Integer -> BVFormula
matchPort p@(Var BV16 _) int = matchGeneric p int
matchPort _ _ = error "matchPort: Invalid Term"

-- | Predicate to match two generic things
matchGeneric p@(Var s _) int | from /= to = And (p `Ge` from) (p `Le` to)
                             | otherwise  = Eq p from
  where I from to = fmap (Lit s) int

-- | Predicate to match established connetions (state == 1)
established :: Term -> BVFormula
established s@(Var BV1 _) = Eq s (Lit BV1 1)
established _ = error "established: Invalid Term"

--------------------------------------------------------------------------------
-- Z3 Predicates

-- | Get top and bottom values for the given bitvector sort
universeBVSort :: BVSort -> Interval Term
universeBVSort sort = I (Lit sort 0) $ Lit sort $ 2^(bvSortSize sort)-1

-- | Get all the variables in the formula
formulaVars :: BVFormula -> S.Set Term
formulaVars = M.keysSet . formulaVarsCount

-- | Get the variables in the Term with their count
termVarsCount :: Term -> M.Map Term Int
termVarsCount t@(Var _ _) = M.singleton t 1
termVarsCount _           = M.empty

-- | Get all the variables in the Formula with their count
formulaVarsCount :: BVFormula -> M.Map Term Int
formulaVarsCount formula = case formula of
  Lt     a b -> M.unionWith (+) (termVarsCount a) (termVarsCount b)
  Gt     a b -> M.unionWith (+) (termVarsCount a) (termVarsCount b)
  Le     a b -> M.unionWith (+) (termVarsCount a) (termVarsCount b)
  Ge     a b -> M.unionWith (+) (termVarsCount a) (termVarsCount b)
  Eq     a b -> M.unionWith (+) (termVarsCount a) (termVarsCount b)
  Ne     a b -> M.unionWith (+) (termVarsCount a) (termVarsCount b)
  And    a b -> M.unionWith (+) (formulaVarsCount a) (formulaVarsCount b)
  Or     a b -> M.unionWith (+) (formulaVarsCount a) (formulaVarsCount b)
  Not    a   -> formulaVarsCount a
  LTrue      -> mempty
  LFalse     -> mempty
  Exists _ b -> formulaVarsCount b
  Forall _ b -> formulaVarsCount b

-- | Size of the bitvector sort
bvSortSize :: BVSort -> Int
bvSortSize BV48 = 48
bvSortSize BV32 = 32
bvSortSize BV16 = 16
bvSortSize BV8  = 8
bvSortSize BV1  = 1

-- | sort of the bitvector size
bvSizeSort :: Int -> BVSort
bvSizeSort 1 = BV1
bvSizeSort 8 = BV8
bvSizeSort 16 = BV16
bvSizeSort 32 = BV32
bvSizeSort 48 = BV48

-- | Convert a Formula to a Z3 Predicate.
--   The variables can be specified or are extracted from the formula.
--   The second return value is a map from the Formula variables to the relative ASTs.
--   Note: different invocations with the same Terms
--         will result in different variables being created
z3Predicate :: MonadZ3 z3 => BVFormula -> Maybe [Term] -> z3 (AST, M.Map Term AST)
z3Predicate formula mVars = do
    let varsSet     = formulaVars formula
    let freeVarsSet = maybe varsSet S.fromList mVars
    vars <- fromSetM (\(Var sort str) -> mkFreshBvVar str $ bvSortSize sort) freeVarsSet
    ast  <- simplify =<< loop formula vars

    return (ast, vars)
  where
    fromSetM    f = sequence . M.fromSet f
    mapWithKeyM f = sequence . M.mapWithKey f

    applyM2 :: Monad m => (a -> b -> m c) -> m a -> m b -> m c
    applyM2 f a b = do x <- a; y <- b; f x y

    z3Term t@(Var _ _)    vars = return $ vars M.! t
    z3Term (Lit sort val) vars = mkBitvector (bvSortSize sort) val

    loop formula vars = case formula of
        Lt     a b -> applyM2 mkBvult (z3Term a vars) (z3Term b vars)
        Gt     a b -> applyM2 mkBvugt (z3Term a vars) (z3Term b vars)
        Le     a b -> applyM2 mkBvule (z3Term a vars) (z3Term b vars)
        Ge     a b -> applyM2 mkBvuge (z3Term a vars) (z3Term b vars)
        Eq     a b -> applyM2 mkEq (z3Term a vars) (z3Term b vars)
        Ne     a b -> mkNot =<< applyM2 mkEq (z3Term a vars) (z3Term b vars)
        And    a b -> applyM2 mkAnd' (loop a vars) (loop b vars)
        Or     a b -> applyM2 mkOr'  (loop a vars) (loop b vars)
        Not    a   -> mkNot =<< loop a vars
        LTrue      -> mkTrue
        LFalse     -> mkFalse
        Exists a b -> do apps <- mapM (toApp <=< (flip z3Term vars)) a
                         mkExistsConst [] apps =<< loop b vars
        Forall a b -> do apps <- mapM (toApp <=< (flip z3Term vars)) a
                         mkForallConst [] apps =<< loop b vars
