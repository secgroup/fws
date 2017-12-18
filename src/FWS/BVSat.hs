{-# OPTIONS_GHC -O2 #-}

{-|
Module      : BVSat
Description : Cubes and multicubes algorithms
Copyright   : (c) 2017 Chiara Bodei <chiara at di.unipi.it>
              (c) 2017 Pierpaolo Degano <degano at di.unipi.it>
              (c) 2017 Riccardo Focardi <focardi at unive.it>
              (c) 2017 Letterio Galletta <galletta at di.unipi.it>
              (c) 2017 Mauro Tempesta <tempesta at unive.it>
              (c) 2017 Lorenzo Veronese <852058 at stud.unive.it>

Functions to work with cubes, multicubes and bitvectors
-}

module FWS.BVSat where

import Control.Monad
import Data.Foldable
import Debug.Trace

import Text.Printf

import Z3.Monad
import qualified Data.Sequence as S

import FWS.Utils

--------------------------------------------------------------------------------
-- UTILS

-- | Evaluate vars in the given model
evalVars :: MonadZ3 z3 => Model -> [AST] -> z3 [BV]
evalVars m vars = maybe (error "evalVars Error") id
                . sequence <$> mapM (evalBV m) vars

--------------------------------------------------------------------------------
-- BV

-- | BitVector type
data BV = BV { bvSize :: !Int, bvVal :: !Integer} deriving (Eq, Ord)

instance Show BV where
  show (BV _ v) = showIP v

-- | Addition for bitvectors
bvAdd :: BV -> Integer -> BV
bvAdd (BV s v) i = BV s (v+i)

-- | Minimum and Maximum value for thw bitvector
bvMin, bvMax :: Int -> BV
bvMin s = BV s 0
bvMax s = BV s (2^s-1)

-- | Convert bitvector to Z3 AST
mkBv :: MonadZ3 z3 => BV -> z3 AST
mkBv (BV s v) = mkBitvector s v

-- | Convert AST to bitvector evaluating it in the model
evalBV :: MonadZ3 z3 => Model -> AST -> z3 (Maybe BV)
evalBV model var = do
  val  <- evalBvu model var
  case val of
    Nothing -> return Nothing
    Just v -> do
      size <- getBvSortSize =<< getSort var
      return $ Just $ BV size v

--------------------------------------------------------------------------------
-- CUBE

-- | Cube as sequence of intervals of bitvectors
data Cube = Cube !(S.Seq (Interval BV)) deriving (Eq, Ord)

instance Show Cube where
  show (Cube ints) = "Cube " ++ (show $ toList ints)

-- | Make a cube from list of singletons
mkCube :: [BV] -> Cube
mkCube = cubeFromList . map (\x -> I x x)

-- | Convert cube to list
cubeList :: Cube -> [Interval BV]
cubeList (Cube ints) = toList ints

-- | Convert list to cube
cubeFromList :: [Interval BV] -> Cube
cubeFromList = Cube . S.fromList

-- | Unconstrain the ith element of the cube
unconstrained :: Cube -> Int -> Cube
unconstrained c@(Cube ints) i = Cube $ S.update i (I min max) ints
  where s = cubeSize c i; min = bvMin s; max = bvMax s

-- | Length of the cube
cubeLen :: Cube -> Int
cubeLen (Cube ints) = S.length ints

-- | Size of the ith bitvector
cubeSize :: Cube -> Int -> Int
cubeSize (Cube ints) i = bvSize $ imin $ ints `S.index` i

-- | Getter for the minimum and maximum ith bitvector
cubeMin, cubeMax :: Cube -> Int -> BV
cubeMin (Cube ints) = imin . S.index ints
cubeMax (Cube ints) = imax . S.index ints

-- | Setter for the minimum and maximum ith bitvector
cubeSetMin, cubeSetMax :: Cube -> Int -> BV -> Cube
cubeSetMin (Cube ints) i min = seq min $ Cube $ S.adjust (\(I _ max) -> I min max) i ints
cubeSetMax (Cube ints) i max = seq max $ Cube $ S.adjust (\(I min _) -> I min max) i ints

-- | Getter for the top or bottom value for the ith bitvector
cubeBottom, cubeTop :: Cube -> Int -> Cube
cubeBottom c i = cubeSetMin c i $ bvMin $ cubeSize c i
cubeTop    c i = cubeSetMax c i $ bvMax $ cubeSize c i

-- | Predicate that checks if vars are inside the cube
inCube :: MonadZ3 z3 => Cube -> [AST] -> z3 AST
inCube (Cube ints) xs = inIntervals xs (toList ints)

inIntervals :: MonadZ3 z3 => [AST] -> [Interval BV] -> z3 AST
inIntervals xs ints = mkAnd =<< concat <$> zipWithM constr xs ints
  where constr x (I min max) =
          sequence [ mkBvuge x =<< mkBv min, mkBvule x =<< mkBv max ]

--------------------------------------------------------------------------------
-- BVSAT

-- | ALL-BVSAT algorithm
allBVSat :: MonadZ3 z3 => AST -> [AST] -> z3 [Cube]
allBVSat frm xs = do s <- mkSolver
                     solverAssert s frm
                     loop s
  where loop s = do
          sat <- solverCheckAndGetModel s
          case sat of
            (Sat, Just m) -> do
              cube  <- expandAll frm xs =<< mkCube <$> evalVars m xs
              solverAssert s =<< mkNot =<< inCube cube xs

              debug $ "+ New Cube: " ++ show cube

              cubes <- loop s
              return $ cube : cubes
            _ -> return []

type CubeGet     = Cube -> Int -> BV
type CubeSet     = Cube -> Int -> BV -> Cube
type CubeTop     = Cube -> Int -> Cube       -- cubeBottom / cubeTop
type Operator z3 = AST -> AST -> z3 AST

minBVSatWith :: MonadZ3 z3
             => CubeGet -> CubeSet -> CubeTop -> Operator z3 -> Integer
             -> AST -> [AST] -> Cube -> Multicube -> Int -> z3 Cube
minBVSatWith get set bottom mkOp incr frm xs c mc i = do
  s <- mkSolver
  solverAssert s =<< mkAndM [mkNot frm, inMulticube cube' xs, mkOp xi =<< mkBv min]
  sat <- solverCheck s
  if not $ sat == Sat then return $ bottom c i else loop s min
  where cube'     = unconstrainedMulticube mc i
        (min, xi) = (get c i, xs!!i)
        loop s l  = do
          sat <- solverCheckAndGetModel s
          case sat of
            (Sat, Just m) -> do
              [l'] <- evalVars m [xi]
              solverAssert s =<< flip mkOp xi =<< mkBv l'
              loop s l'
            _ -> return $ set c i $ bvAdd l incr

-- | min/maxBVSAT algorithms
minBVSat', maxBVSat' :: MonadZ3 z3 => AST -> [AST] -> Cube -> Multicube -> Int -> z3 Cube
minBVSat' = minBVSatWith cubeMin cubeSetMin cubeBottom mkBvult 1
maxBVSat' = minBVSatWith cubeMax cubeSetMax cubeTop    mkBvugt (-1)

-- | Expand ith interval in the cube using the given formula
expandInterval :: MonadZ3 z3 => AST -> [AST] -> Cube -> Multicube -> Int -> z3 Cube
expandInterval frm xs c mc i = do
  min <- minBVSat frm xs c   mc i
  max <- maxBVSat frm xs min mc i
  return max

-- | Expand all the intervals in the cube using the given formula
expandAll :: MonadZ3 z3 => AST -> [AST] -> Cube -> z3 Cube
expandAll frm xs c = foldM (\c -> expandInterval frm xs c (mkMulticube c)) c [0..cubeLen c-1]

--------------------------------------------------------------------------------
-- MULTICUBE

-- | Multicube as a sequence of lists of intervals of bitvectors
data Multicube = Multicube (S.Seq [Interval BV]) deriving (Eq, Ord)

instance Show Multicube where
  show (Multicube ints) = "Multicube " ++ (show $ toList ints)

-- | Make a multicube from a cube
mkMulticube :: Cube -> Multicube
mkMulticube (Cube ints) = Multicube $ fmap return ints

-- | Predicate that checks if vars are inside the multicube
inMulticube :: MonadZ3 z3 => Multicube -> [AST] -> z3 AST
inMulticube (Multicube sq) vars = mkAnd =<< zipWithM orIn vars (toList sq)
  where orIn v ints = mkOr =<< mapM (inInt v) ints
        inInt v (I min max) = mkAnd =<< sequence [mkBvuge v =<< mkBv min
                                                 ,mkBvule v =<< mkBv max]

multicubeList :: Multicube -> [[Interval BV]]
multicubeList (Multicube ints) = toList ints

unconstrainedMulticube :: Multicube -> Int -> Multicube
unconstrainedMulticube c@(Multicube ints) i = Multicube $ S.update i [I min max] ints
  where s = multiCubeSize c i; min = bvMin s; max = bvMax s

multiCubeSize :: Multicube -> Int -> Int
multiCubeSize (Multicube ints) i = bvSize $ imin $ head $ ints `S.index` i

--------------------------------------------------------------------------------
-- ALLBVSAT*

-- | ALLBVSAT* algorithm
allBVSat' :: MonadZ3 z3 => AST -> [AST] -> z3 [Multicube]
allBVSat' frm xs = do s <- mkSimpleSolver
                      solverAssert s frm
                      loop s []
  where loop s mcubes = do
          sat <- solverCheckAndGetModel s
          case sat of
            (Sat, Just m) -> do
              res <- evalVars m xs
              mcubes' <- forM mcubes $ \mc -> do
                mc' <- extend frm xs res mc
                solverAssert s =<< mkNot =<< inMulticube mc' xs
                return $! mc'

              res' <- solverLocal s $ do
                solverAssert s frm
                solverAssert s =<< mkAnd =<< zipWithM mkEq xs =<< mapM mkBv res
                solverCheck s

              if (res' == Sat)
                then do
                  cube <- expandAll frm xs $ mkCube res
                  solverAssert s =<< mkNot =<< inCube cube xs

                  debug $ "+ New Cube: " ++ show cube

                  loop s (mkMulticube cube : mcubes')
                else loop s mcubes'
            _ -> return $ reverse mcubes

extend :: MonadZ3 z3 => AST -> [AST] -> [BV] -> Multicube -> z3 Multicube
extend frm xs vals (Multicube ints) = do
  s <- mkSolver --SimpleSolver
  solverAssert s =<< mkNot frm
  fmap (Multicube . S.fromList) $
   forM (zip3 [0..] vals (toList ints)) $ \(i, v, int) -> do
    if v `inside` int then return int
      else do
        let ints' = S.adjust (const $ [I v v]) i ints
        frm'      <- inMulticube (Multicube ints') xs
        res       <- solverLocal s $ solverAssert s frm' >> solverCheck s
        case res of
          Sat -> return int
          _   -> do
                (Cube nints) <- expandInterval frm xs (Cube $ fmap head ints') (Multicube ints') i

                debug $ "+ Expand ("++ show i++"): "++ show (nints `S.index` i)

                return $ (nints`S.index`i) : int
  where
    inside x = or . map (\(I b e) -> x >= b && x <= e)

--------------------------------------------------------------------------------
-- BINARY SEARCH

minBVSat, maxBVSat :: MonadZ3 z3 => AST -> [AST] -> Cube -> Multicube -> Int -> z3 Cube

minBVSat frm xs c mc i = do
  s <- mkSimpleSolver
  solverAssert s =<< mkAndM [mkNot frm, inMulticube cube' xs, mkBvult xi =<< mkBv min]
  sat <- solverCheck s
  if not $ sat == Sat then return $ cubeBottom c i else do
    m <- solverGetModel s
    [low]  <- evalVars m [xi]
    loop s low min
  where cube'     = unconstrainedMulticube mc i
        (min, xi) = (cubeMin c i, xs!!i)
        loop s low high = do
          if lowVal >= highVal -1
            then do solverAssert s =<< flip mkBvult xi =<< mkBv low -- > low
                    sat <- solverCheck s
                    return $ cubeSetMin c i $ bvAdd (case sat of
                      Sat -> high
                      _   -> low) 1
            else do let mid = BV size $ (lowVal + highVal) `div` 2
                    solverPush s
                    solverAssert s =<< flip mkBvult xi =<< mkBv mid
                    sat <- solverCheckAndGetModel s
                    case sat of
                      (Sat, Just m) -> do
                        [low'] <- evalVars m [xi]
                        loop s low' high
                      _ -> do solverPop s 1
                              loop s low mid
          where BV _ lowVal     = low
                BV size highVal = high

maxBVSat frm xs c mc i = do
  s <- mkSimpleSolver
  solverAssert s =<< mkAndM [mkNot frm, inMulticube cube' xs, mkBvugt xi =<< mkBv low]
  sat <- solverCheck s
  if not $ sat == Sat then return $ cubeTop c i else do
    m <- solverGetModel s
    [high]  <- evalVars m [xi]
    loop s low high
  where cube'     = unconstrainedMulticube mc i
        (low, xi) = (cubeMax c i, xs!!i)

        loop s low high = do
          if highVal <= lowVal +1
            then do solverAssert s =<< flip mkBvugt xi =<< mkBv high -- < high
                    sat <- solverCheck s
                    return $ cubeSetMax c i $ bvAdd (case sat of
                      Sat -> low
                      _   -> high) (-1)
            else do let mid = BV size $ (lowVal + highVal) `div` 2
                    solverPush s
                    solverAssert s =<< flip mkBvugt xi =<< mkBv mid
                    sat <- solverCheckAndGetModel s
                    case sat of
                      (Sat, Just m) -> do
                        [high'] <- evalVars m [xi]
                        loop s low high'
                      _ -> do solverPop s 1
                              loop s mid high
          where BV _ lowVal     = low
                BV size highVal = high
