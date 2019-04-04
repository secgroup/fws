{-# OPTIONS_GHC -O2 #-}
{-# LANGUAGE BangPatterns #-}
{-# LANGUAGE NamedFieldPuns #-}
{-# LANGUAGE RecordWildCards #-}
{-# LANGUAGE DeriveFunctor #-}
{-# LANGUAGE DeriveTraversable #-}

{-|
Module      : FWS.Types
Description : FWS Types
Copyright   : (c) 2017 Chiara Bodei <chiara at di.unipi.it>
              (c) 2017 Pierpaolo Degano <degano at di.unipi.it>
              (c) 2017 Riccardo Focardi <focardi at unive.it>
              (c) 2017 Letterio Galletta <galletta at di.unipi.it>
              (c) 2017 Mauro Tempesta <tempesta at unive.it>
              (c) 2017 Lorenzo Veronese <852058 at stud.unive.it>
-}


module FWS.Types where

import qualified Data.Map            as     M
import           Control.Monad.State hiding (state)
import           Data.Foldable              (toList)

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
                        , srcMac   :: !a
                        , dstMac   :: !a
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
mkPacket n = Packet {srcIp, srcPort, dstIp, dstPort, srcMac, dstMac, protocol, state}
  where srcIp    = Var BV32 $ "srcIp_"    ++ show n
        srcPort  = Var BV16 $ "srcPort_"  ++ show n
        dstIp    = Var BV32 $ "dstIp_"    ++ show n
        dstPort  = Var BV16 $ "dstPort_"  ++ show n
        srcMac   = Var BV48 $ "srcMAC_"   ++ show n
        dstMac   = Var BV48 $ "dstMAC_"   ++ show n
        protocol = Var BV8  $ "protocol_" ++ show n
        state    = Var BV1  $ "state_"    ++ show n

-- | Create a Packet from a list
packetFromList :: [a] -> PPacket a
packetFromList [srcIp, srcPort, dstIp, dstPort, srcMac, dstMac, protocol, state] = Packet{..}
packetFromList _ = error "packetFromList: Invalid List"

-- | Zip two packets with a function
zipPacketsWith :: (a -> b -> c) -> PPacket a -> PPacket b -> PPacket c
zipPacketsWith f a b = packetFromList $ zipWith f (toList a) (toList b)

-- | Instantiate a packet from a multicube and its variables
instantiate :: (Functor f, Eq a)
                 => [a] -> Multicube -> f a -> f (Maybe [Interval BV])
instantiate vars mcb = fmap (flip lookup $ zip vars $ multicubeList mcb)

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

--------------------------------------------------------------------------------
-- MRULES

data LocalFlag = Local | NoLocal | Both deriving (Show, Eq)

-- | Multicubes rule
data MRule = MRule !IMPacket !IMPacket deriving (Eq, Show)

-- | Make a MRule from a pair of IMPacket
mkMRule :: IMPacket -> IMPacket -> MRule
mkMRule pin pout = MRule pin (without pin pout)
  where without p = zipPacketsWith (\i o -> if i == o then Nothing else o) p
