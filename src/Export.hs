{-# LANGUAGE ForeignFunctionInterface, TemplateHaskell #-}


{-|
Module      : Export
Description : Pyhton-Exported Synthesis functions
Copyright   : (c) 2017 Chiara Bodei <chiara at di.unipi.it>
              (c) 2017 Pierpaolo Degano <degano at di.unipi.it>
              (c) 2017 Riccardo Focardi <focardi at unive.it>
              (c) 2017 Letterio Galletta <galletta at di.unipi.it>
              (c) 2017 Mauro Tempesta <tempesta at unive.it>
              (c) 2017 Lorenzo Veronese <852058 at stud.unive.it>
-}

module Export where

import System.IO.Unsafe (unsafePerformIO)

import Data.Int ( Int64(..) )
import Data.Foldable (toList)
import Foreign.HaPy
import qualified FWS as SY
import qualified FWS.BVSat as BV
import qualified FWS.Utils as U

-------------------------------------------------------------------------------
-- TYPES

-- wrapper type
newtype Firewall = Firewall { getFiewall :: SY.Firewall String }

-------------------------------------------------------------------------------
-- Utils

getLocal :: Int -> SY.LocalFlag
getLocal = flip getFlag [SY.Both, SY.Local, SY.NoLocal]

getFlag :: Int -> [a] -> a
getFlag n lst | n >= (length lst) = error $ "Invalid Flag Argument " ++ show n
              | otherwise         = lst !! n

-------------------------------------------------------------------------------
-- PYTHON EXPORTS

make_firewall :: String -> String -> String -> [String] -> IO Firewall
make_firewall diagramFile chainFile chains locals = do
  diagram <- readFile diagramFile
  return $ Firewall $
    SY.mkFirewall diagramFile diagram chainFile chains $ U.parseIPs locals

synthesize :: Firewall -> [String] -> Int -> Int -> String -> IO [SY.MRule]
synthesize firewall locals localSrc' localDst' query =
  SY.synthesizeFirewall (U.parseIPs locals) localSrc localDst query (getFiewall firewall)
  where (localSrc, localDst) = (getLocal localSrc', getLocal localDst')

synthesize_nd :: Firewall -> [String] -> Int -> Int -> String -> IO [SY.MRule]
synthesize_nd firewall locals localSrc' localDst' query =
  SY.synthesizeND  (U.parseIPs locals) localSrc localDst query (getFiewall firewall)
  where (localSrc, localDst) = (getLocal localSrc', getLocal localDst')

mrule_list :: SY.MRule -> [[[[Int64]]]]
mrule_list (SY.MRule p p') = (convertPacket p):[convertPacket p']
  where convertPacket = map (maybe [] (map (map (fromIntegral . BV.bvVal) . toList))) . toList

implication :: Firewall -> Firewall -> [String] -> Int -> Int -> String -> IO Bool
implication fw fw' locals localSrc' localDst' query = U.evalZ3Model $
  SY.policyImplication (getFiewall fw) (getFiewall fw') query (U.parseIPs locals) localSrc localDst
  where
    (localSrc, localDst) = (getLocal localSrc', getLocal localDst')

equivalence :: Firewall -> Firewall -> [String] -> Int -> Int -> String -> IO Bool
equivalence fw fw' locals localSrc' localDst' query = U.evalZ3Model $
  SY.policyEquivalence (getFiewall fw) (getFiewall fw') query (U.parseIPs locals) localSrc localDst
  where
    (localSrc, localDst) = (getLocal localSrc', getLocal localDst')

difference :: Firewall -> Firewall -> [String] -> Int -> Int -> String -> IO [[SY.MRule]]
difference fw fw' locals localSrc' localDst' query =
  SY.synthesizeDiff (getFiewall fw) (getFiewall fw') query (U.parseIPs locals) localSrc localDst
  >>= \(p,m) -> return [p,m]
  where
    (localSrc, localDst) = (getLocal localSrc', getLocal localDst')

set_verbose :: Bool -> IO ()
set_verbose v = U.setDebug v

initHaPy
pythonExport 'mrule_list
pythonExport 'synthesize
pythonExport 'synthesize_nd
pythonExport 'make_firewall
pythonExport 'implication
pythonExport 'equivalence
pythonExport 'difference
pythonExport 'set_verbose
