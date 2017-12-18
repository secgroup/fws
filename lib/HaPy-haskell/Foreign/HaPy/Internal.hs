module Foreign.HaPy.Internal (
  sizeOfList,
  peekList,
  pokeList,
  copyList,
  getVarIType
) where

import Foreign.C ( CInt )
import Foreign.Marshal.Array ( pokeArray, peekArray )
import Foreign.Marshal.Alloc ( mallocBytes )
import Foreign.Storable ( Storable(..) )
import Foreign.Ptr ( Ptr, plusPtr, castPtr, alignPtr )

import Language.Haskell.TH
import Data.Foldable ( find )
import Language.Haskell.TH.Datatype


cInt :: CInt
cInt = undefined

lenPtr :: Storable a => Ptr [a] -> Ptr CInt
lenPtr = castPtr

arrPtr :: Storable a => Ptr [a] -> Ptr a
arrPtr ptr = castPtr $ (ptr `plusPtr` sizeOf cInt) `alignPtr` alignment (ptrElem ptr)
  where ptrElem :: Ptr [a] -> a
        ptrElem = undefined

sizeOfList :: Storable a => [a] -> Int
sizeOfList xs = alignedIntSize + length xs * sizeOf (head xs)
  where alignedIntSize = max (sizeOf cInt) (alignment $ head xs)

peekList :: Storable a => Ptr [a] -> IO [a]
peekList ptr = do
  len <- peek $ lenPtr ptr
  peekArray (fromIntegral len) $ arrPtr ptr

pokeList :: Storable a => Ptr [a] -> [a] -> IO ()
pokeList ptr xs = do
  poke (lenPtr ptr) (fromIntegral $ length xs)
  pokeArray (arrPtr ptr) xs

copyList :: Storable a => [a] -> IO (Ptr [a])
copyList xs = do
  ptr <- mallocBytes $ sizeOfList xs
  pokeList ptr xs
  return ptr

-- | Template Haskell 2.8 -> 2.11 compatibility trick:
--     the arity of the VarI connstructor has chenaged, so we
--     need to use the correct one
getVarIType :: Q Exp
getVarIType = do
  datatype <- reifyDatatype ''Info
  let Just numArgs = fmap (length . constructorFields)
                   $ find (\x -> (constructorName x) == 'VarI) $ datatypeCons datatype
  case numArgs of
    3 -> [e| \info -> let (VarI _ t _) = info in t |]
    4 -> [e| \info -> let (VarI _ t _ _) = info in t|]
    _ -> error "Invalid number of agrument for VarI connstructor!"
