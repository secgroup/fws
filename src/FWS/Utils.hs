{-# OPTIONS_GHC -O2 #-}
{-# LANGUAGE DeriveTraversable #-}
{-# LANGUAGE DeriveFunctor #-}

{-|
Module      : Utils
Description : Intervals, IPs and Z3 utils
Copyright   : (c) 2017 Chiara Bodei <chiara at di.unipi.it>
              (c) 2017 Pierpaolo Degano <degano at di.unipi.it>
              (c) 2017 Riccardo Focardi <focardi at unive.it>
              (c) 2017 Letterio Galletta <galletta at di.unipi.it>
              (c) 2017 Mauro Tempesta <tempesta at unive.it>
              (c) 2017 Lorenzo Veronese <852058 at stud.unive.it>

Some utilities to manage Intervals, to read and write
IP address intervals ad to simplify some Z3.Monad operations
-}

module FWS.Utils where

import Control.Monad
import Control.Monad.State
import Data.Bits
import Data.Char
import Data.List
import Data.Maybe
import Text.Parsec
import Text.Printf
import qualified Data.Map as M

import System.IO
import System.IO.Unsafe
import Data.IORef

import Debug.Trace

import Z3.Monad

--------------------------------------------------------------------------------
-- GENERAL UTILS

-- | Simple Interval record
data Interval a = I { imin :: !a, imax :: !a }
                deriving (Eq, Ord, Functor, Foldable, Traversable)

instance Show a => Show (Interval a) where
  show (I a b) = "{"++show a++".."++show b++"}"

-- | Interval of a single value
singleton :: a -> Interval a
singleton a = I a a

--------------------------------------------------------------------------------
-- DEBUG

-- | unsafePerformIO Hack to have a global flag
{-# NOINLINE debugFlag #-}
debugFlag :: IORef Bool
debugFlag = unsafePerformIO $ newIORef False

-- | Set debug mode
setDebug :: (MonadIO m) => Bool -> m ()
setDebug = liftIO . writeIORef debugFlag

-- | Print str on stderr if in debug mode 
debug :: (MonadIO m) => String -> m ()
debug str = flip when (liftIO $ hPutStrLn stderr str)
          =<< liftIO (readIORef debugFlag)
  
--------------------------------------------------------------------------------
-- PROGRES BAR

showProgressBar :: (PrintfArg a, Integral a) => a -> a -> String
showProgressBar n len =
  printf "\rSolving: [%s] (%5d/%5d) %3.2f%%\r" filling n len percentage
  where filling    = replicate fnum '#' ++ replicate (ftot-fnum) ' '
        ftot       = 50
        fnum       = truncate $ 50*(percentage/100)
        percentage = fromIntegral n / (fromIntegral len) * 100 :: Double

printProgress :: (MonadIO m, PrintfArg a, Integral a) => a -> a -> m ()
printProgress n = liftIO . hPutStr stderr . showProgressBar n

--------------------------------------------------------------------------------
-- Z3 UTILS

-- | Make StateT a an instance of MoandZ3
instance MonadZ3 z3 => MonadZ3 (StateT a z3) where
  getContext = lift $ getContext

-- | Make AST Node from list of monadic values
mkAndM, mkOrM :: MonadZ3 z3 => [z3 AST] -> z3 AST
mkAndM = mkAnd <=< sequence
mkOrM  = mkOr  <=< sequence

-- | Make AST Node from single values
mkAnd', mkOr' :: MonadZ3 z3 => AST -> AST -> z3 AST
mkAnd' a b = mkAnd [a,b]
mkOr' a b = mkOr [a,b]

-- evalBv bug:
--   evalbv = modelEval  >>> mkBv2int >>> getNumeralString
--   astToString <<< mkBvInt = "(bv2int #x00...)", it fails with getNumeralString
-- Skipping mkBv2int solves the problem
-- but we do not have the signed conversion.
-- | Evaluate the AST node in the given model as an unsigned bitvector
evalBvu :: MonadZ3 z3 => Model -> AST -> z3 (Maybe Integer)
evalBvu model var = sequence . fmap (fmap read . getNumeralString)
                  =<< modelEval model var True

-- | Run Z3 Monad with option MODEL
evalZ3Model :: Z3 a -> IO a
evalZ3Model = evalZ3With (opt "MODEL" True)

--------------------------------------------------------------------------------
-- IP ADDRESSES

-- | Parse an IP address range in the form:
--   *               -> range from 0 to 2^32-1
--   x.x.x.x         -> Single Address
--   x.x.x.x/n       -> Subnet Range
--   x.x.x.x-x.x.x.x -> Address Range
parseIP :: String -> Interval Integer
parseIP str = case parse ip "" str of
  Right int -> int
  Left  e   -> error $ show e

-- | Parse a list of IPs
parseIPs :: [String] -> [Integer]
parseIPs = map (imin . parseIP)

-- | Parser for IP address ranges
ip :: Parsec String () (Interval Integer)
ip = try star <|> try range <|> subnet
  where star     = char '*' >> return (I 0 $ 2^32-1)
        range    = I <$> qddn <*> (char '-' *> qddn)
        subnet   = do addr <- qddn
                      sn   <- option 32 (char '/' >> natural)
                      when (sn > 32) $ fail "Invalid Subnet Mask"
                      let (a,b) = mask addr (fromIntegral $ 32-sn)
                      return $ I a b
        qddn     = do addr <- sepBy natural (char '.')
                      when (length addr /= 4) $ fail "Invalid IP Address"
                      return $ fromDotDecimal addr
        mask v s = (shift (shift v (-s)) s, v .|. 2^s-1)

-- | Parser for MAC addresses
mac :: Parsec String () (Interval Integer)
mac = try star <|> try range <|> try single
  where star    = char '*' >> return (I 0 $ 2^48-1)
        range   = I <$> sixhex <*> (char '-' *> sixhex)
        single  = sixhex >>= \x ->return $ I x x
        sixhex  = do addr <- sepBy hexByte (char ':')
                     when (length addr /= 6) $ fail "Invalid MAC Address"
                     return $ fromDotDecimal addr
        hexByte = parseHex <$> ((:) <$> hexchar <*> ((:) <$> hexchar <*> pure []))
        hexchar = oneOf $ ['a'..'f'] ++ ['A'..'F'] ++ ['0'..'9']
        parseHex = fromIntegral . foldl' f 0
         where f n c = 16*n + (fromJust $ elemIndex (toUpper c) "0123456789ABCDEF")

-- | Natural number parser
natural :: Parsec String () Integer
natural = read <$> many1 digit

-- | Parse a protocol name
proto :: Parsec String () Integer
proto = do name <- many1 (lower <|> oneOf "-/.")
           case M.lookup name protocolNumbers of
             Nothing -> fail $ "Invalid Protocol "++ show name
             Just i -> return $ fromIntegral i

-- | Show IP Address Range
showIPRange :: Interval Integer -> String
showIPRange (I 0 n) | n == 2^32-1 = "*"
showIPRange (I f t) | f == t = showIP f
                    | isJust snum = showIP f ++ "/" ++ show (fromJust snum)
                    | otherwise   = showIP f ++ "-" ++ showIP t
                    where snum = cidrSubnet (I f t)

-- | Get subnet number for CIDR Notation
cidrSubnet :: (Interval Integer) -> Maybe Int
cidrSubnet (I 0 _) = Nothing
cidrSubnet (I a b) = checkSuffix $ stripPrefix $ zip ba bb
  where (ba, bb) = (binary 32 a, binary 32 b)
        stripPrefix = dropWhile (uncurry (==))
        checkSuffix rest | all (\(x,y) -> x == 0 && y == 1) rest = Just $ 32 - (length rest)
                         | otherwise = Nothing

-- | Get the last binary digits of a number
binary :: (Num a, Bits a) => Int -> a -> [a]
binary p 0 = [0]
binary p n = reverse . take p $ (unfoldr bindigit n) ++ repeat 0
  where bindigit 0 = Nothing
        bindigit n = Just (n.&.1, n`shiftR`1)

-- | Show IP Address
showIP :: Integer -> String
showIP v = concat $ intersperse "." $ map show $ quadDotDecimal v

-- | Show Port Range
showPortRange :: Interval Integer -> String
showPortRange port@(I f t) | port == (I 0 $ 2^16-1) = "*"
                           | f == t = show f
                           | otherwise = show f ++ "-" ++ show t

-- | Show Protocol Range
showProtoRange :: Interval Integer -> String
showProtoRange proto@(I f t) | proto == (I 0 255) = "*"
                             | f == t = protoName f
                             | otherwise = show f ++ "-" ++ show t

-- | Show protocol name for well known protocols
protoName :: Integer -> String
protoName s  = maybe (show s) id $ M.lookup (fromIntegral s) protocolNames

-- | Show IP and Port ranges
showIPPort :: Interval Integer -> Interval Integer -> String
showIPPort ip port@(I f t) | port == (I 0 $ 2^16-1) = showIPRange ip
                           | otherwise = showIPRange ip ++ ":" ++ showPortRange port

-- | Convert dot decimal notation to number
fromDotDecimal :: (Num a, Bits a) => [a] -> a
fromDotDecimal = foldl1 (.|.)
               . zipWith (flip shiftL) [0,8..]
               . reverse . map (.&. 0xff)

-- | Convert number to dot decimal notation
toDotDecimal :: (Num a, Bits a) => a -> [a]
toDotDecimal = reverse . go
  where go n | n == 0    = []
             | otherwise = n .&. 0xff : go (n `shiftR` 8)

-- | Convert number to quad dot decimal notation
quadDotDecimal :: (Num a, Bits a) => a -> [a]
quadDotDecimal = reverse . take 4 . (++(repeat 0))
               . reverse . toDotDecimal

--------------------------------------------------------------------------------
-- PROTOCOLS

protocols = unsafePerformIO readProtocols
  where valid line    = line /= "" && not ("#" `isPrefixOf` line)
        readProtocols = map (take 2 . words) . filter valid . lines <$> readFile "/etc/protocols"

protocolNumbers :: M.Map String Int
protocolNumbers = M.fromList [ (n,read v) | [n,v] <- protocols ]

protocolNames :: M.Map Int String
protocolNames = M.fromList [ (read v,n) | [n,v] <- protocols ]

