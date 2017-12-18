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

getTableStyle :: Int -> SY.TableConstructor
getTableStyle = flip getFlag [SY.unicodeTable, SY.asciiTable, SY.texTable]

getLocal :: Int -> SY.LocalFlag
getLocal = flip getFlag [SY.Both, SY.Local, SY.NoLocal]

getNat :: Int -> SY.NatFlag
getNat = flip getFlag [SY.ShowAll, SY.ShowFilter, SY.ShowNat]

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

mrule_list :: SY.MRule -> [[[[Int]]]]
mrule_list (SY.MRule p p') = (convertPacket p):[convertPacket p']
  where convertPacket = map (maybe [] (map (map (fromIntegral . BV.bvVal) . toList))) . toList

mrule_table :: [SY.MRule] -> Int -> [String] -> Int -> Int -> Int -> IO ()
mrule_table rules tableStyle' locals localSrc' localDst' nat' =
  SY.printTables (U.parseIPs locals) tableStyle localSrc localDst nat rules
  where
    (localSrc, localDst) = (getLocal localSrc', getLocal localDst')
    nat                  = getNat nat'
    tableStyle           = getTableStyle tableStyle'

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

diff_table :: Int -> String -> String -> [SY.MRule] -> [SY.MRule] -> [String] -> Int -> Int  -> IO ()
diff_table tableStyle' name name' rules rules' locals localSrc' localDst' =
  SY.printDiffTable tableStyle name name' rules rules' (U.parseIPs locals) localSrc localDst
  where
    (localSrc, localDst) = (getLocal localSrc', getLocal localDst')
    tableStyle = getTableStyle tableStyle'


set_verbose :: Bool -> IO ()
set_verbose v = U.setDebug v

initHaPy
pythonExport 'mrule_list
pythonExport 'synthesize
pythonExport 'make_firewall
pythonExport 'mrule_table
pythonExport 'implication
pythonExport 'equivalence
pythonExport 'difference
pythonExport 'diff_table
pythonExport 'set_verbose
