{-# OPTIONS_GHC -O2 #-}
{-# LANGUAGE BangPatterns #-}
{-# LANGUAGE NamedFieldPuns #-}
{-# LANGUAGE RecordWildCards #-}
{-# LANGUAGE DeriveFunctor #-}
{-# LANGUAGE DeriveTraversable #-}

{-|
Module      : FWS.Parsers
Description : Chain and Control Diagram Parsers
Copyright   : (c) 2017 Chiara Bodei <chiara at di.unipi.it>
              (c) 2017 Pierpaolo Degano <degano at di.unipi.it>
              (c) 2017 Riccardo Focardi <focardi at unive.it>
              (c) 2017 Letterio Galletta <galletta at di.unipi.it>
              (c) 2017 Mauro Tempesta <tempesta at unive.it>
              (c) 2017 Lorenzo Veronese <852058 at stud.unive.it>
-}


module FWS.Parsers where

import           Control.Monad
import           Data.Char                  (isLower, isSpace)
import qualified Data.Map            as     M
import           Text.Parsec         hiding (State)

import           FWS.BVSat
import           FWS.BVPredicates
import           FWS.Utils
import           FWS.Types

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
pvariable =  srcIp  <$ symbol "srcIp"  <|> srcPort  <$ symbol "srcPort"
         <|> dstIp  <$ symbol "dstIp"  <|> dstPort  <$ symbol "dstPort"
         <|> srcMac <$ symbol "srcMac" <|> dstMac   <$ symbol "dstMac"
         <|> state  <$ symbol "state"  <|> protocol <$ symbol "protocol"

ppvariable :: Parsec String () ((Packet, Packet) -> Term)
ppvariable =  try ( (srcIp  . snd) <$ symbol "srcIp'" ) <|> try ( (srcPort  . snd) <$ symbol "srcPort'" )
          <|> try ( (dstIp  . snd) <$ symbol "dstIp'" ) <|> try ( (dstPort  . snd) <$ symbol "dstPort'" )
          <|> try ( (state  . fst) <$ symbol "state"  ) <|> try ( (protocol . fst) <$ symbol "protocol" )
          <|> try ( (srcIp  . fst) <$ symbol "srcIp"  ) <|> try ( (srcPort  . fst) <$ symbol "srcPort"  )
          <|> try ( (dstIp  . fst) <$ symbol "dstIp"  ) <|> try ( (dstPort  . fst) <$ symbol "dstPort"  )
          <|> try ( (srcMac . fst) <$ symbol "srcMac" ) <|> try ( (dstMac   . fst) <$ symbol "dstMac"   )

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

-- | Matches a single term that can be "var == addr" or "var == value"
term :: Parsec String () (a -> Term) -> Parsec String () (a -> BVFormula)
term variable = (\p -> LTrue) <$ symbol "true"
     <|> do
  var <- variable
  symbol "=="
  star <|> try (addr var) <|> try (macaddr var) <|> number var
  where star       = (\p -> LTrue) <$ char '*'
        addr var    = do addr <- ip
                         return $ \p -> matchIPInterval (var p) addr
        macaddr var = do addr <- mac
                         return $ \p -> matchMACInterval (var p) addr
        number var  = do port <- (singleton <$> proto) <|> range
                         return $ \p -> matchGeneric (var p) port

-- | Valid identifier with alphanumeric, "-" and "_"
identifier :: Parsec String () String
identifier = many1 (alphaNum <|> char '-' <|> char '_' <|> char '.')

--------------------------------------------------------------------------------
-- CONTROL DIAGRAM PARSER

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
