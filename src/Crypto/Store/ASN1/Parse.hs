-- |
-- Module      : Crypto.Store.ASN1.Parse
-- License     : BSD-style
-- Maintainer  : Olivier Chéron <olivier.cheron@gmail.com>
-- Stability   : experimental
-- Portability : unknown
--
-- Parser combinators for ASN.1 stream.  Similar to "Data.ASN1.Parse" but
-- with the following additions:
--
-- * Parsed stream is annotated, i.e. parser input is @('ASN1', e)@ instead of
--   @'ASN1'@.  Main motivation is to allow to parse a sequence of 'ASN1Repr'
--   and hold the exact binary content that has been parsed.  As consequence,
--   no @getObject@ function is provided.  Function 'withAnnotations' runs
--   a parser and returns all annotations consumed in a monoid concatenation.
--
-- * The parser implements 'Alternative' and 'MonadPlus'.
--
-- * The 'fail' function returns a parse error so that pattern matching makes
--   monadic parsing code easier to write.
module Crypto.Store.ASN1.Parse
    ( ParseASN1
    -- * run
    , runParseASN1State
    , runParseASN1State_
    , runParseASN1
    , runParseASN1_
    , throwParseError
    -- * combinators
    , onNextContainer
    , onNextContainerMaybe
    , getNextContainer
    , getNextContainerMaybe
    , getNext
    , getNextMaybe
    , hasNext
    , getMany
    , withAnnotations
    ) where

import Data.ASN1.Types
import Data.Monoid
import Control.Applicative
import Control.Arrow (first)
import Control.Monad (MonadPlus(..), liftM2)
import Control.Monad.Fail

data State e = State [(ASN1, e)] !e

-- | ASN1 parse monad
newtype ParseASN1 e a = P { runP :: State e -> Either String (a, State e) }

instance Functor (ParseASN1 e) where
    fmap f m = P (fmap (first f) . runP m)
instance Applicative (ParseASN1 e) where
    pure a = P $ \s -> Right (a, s)
    (<*>) mf ma = P $ \s ->
        case runP mf s of
            Left err      -> Left err
            Right (f, s2) ->
                case runP ma s2 of
                    Left err      -> Left err
                    Right (a, s3) -> Right (f a, s3)
instance Alternative (ParseASN1 e) where
    empty = throwParseError "empty"
    (<|>) = mplus
instance Monad (ParseASN1 e) where
    return      = pure
    (>>=) m1 m2 = P $ \s ->
        case runP m1 s of
            Left err      -> Left err
            Right (a, s2) -> runP (m2 a) s2
    fail        = throwParseError
instance MonadFail (ParseASN1 e) where
    fail = throwParseError
instance MonadPlus (ParseASN1 e) where
    mzero = throwParseError "mzero"
    mplus m1 m2 = P $ \s ->
        case runP m1 s of
            Left  _ -> runP m2 s
            success -> success

get :: ParseASN1 e (State e)
get = P $ \stream -> Right (stream, stream)

put :: State e -> ParseASN1 e ()
put stream = P $ \_ -> Right ((), stream)

-- | throw a parse error
throwParseError :: String -> ParseASN1 e a
throwParseError s = P $ \_ -> Left s

wrap :: ASN1 -> (ASN1, ())
wrap a = (a, ())

unwrap :: (ASN1, ()) -> ASN1
unwrap (a, ()) = a

-- | run the parse monad over a stream and returns the result and the remaining ASN1 Stream.
runParseASN1State :: ParseASN1 () a -> [ASN1] -> Either String (a, [ASN1])
runParseASN1State f a = do
    (a', list) <- runParseASN1State_ f (map wrap a)
    return (a', map unwrap list)

-- | run the parse monad over a stream and returns the result and the remaining ASN1 Stream.
runParseASN1State_ :: Monoid e => ParseASN1 e a -> [(ASN1, e)] -> Either String (a, [(ASN1, e)])
runParseASN1State_ f a = do
    (r, State a' _) <- runP f (State a mempty)
    return (r, a')

-- | run the parse monad over a stream and returns the result.
--
-- If there's still some asn1 object in the state after calling f,
-- an error will be raised.
runParseASN1 :: ParseASN1 () a -> [ASN1] -> Either String a
runParseASN1 f s = runParseASN1_ f (map wrap s)

-- | run the parse monad over a stream and returns the result.
--
-- If there's still some asn1 object in the state after calling f,
-- an error will be raised.
runParseASN1_ :: Monoid e => ParseASN1 e a -> [(ASN1, e)] -> Either String a
runParseASN1_ f s =
    case runP f (State s mempty) of
        Left err              -> Left err
        Right (o, State [] _) -> Right o
        Right (_, State er _) ->
            Left ("runParseASN1_: remaining state " ++ show (map fst er))

-- | get next element from the stream
getNext :: Monoid e => ParseASN1 e ASN1
getNext = do
    list <- get
    case list of
        State []        _  -> throwParseError "empty"
        State ((h,e):l) es -> put (State l (es <> e)) >> return h

-- | get many elements until there's nothing left
getMany :: ParseASN1 e a -> ParseASN1 e [a]
getMany getOne = do
    next <- hasNext
    if next
        then liftM2 (:) getOne (getMany getOne)
        else return []

-- | get next element from the stream maybe
getNextMaybe :: Monoid e => (ASN1 -> Maybe a) -> ParseASN1 e (Maybe a)
getNextMaybe f = do
    list <- get
    case list of
        State []        _  -> return Nothing
        State ((h,e):l) es -> let r = f h
                               in do case r of
                                         Nothing -> put list
                                         Just _  -> put (State l (es <> e))
                                     return r

-- | get next container of specified type and return all its elements
getNextContainer :: Monoid e => ASN1ConstructionType -> ParseASN1 e [(ASN1, e)]
getNextContainer ty = do
    list <- get
    case list of
        State []        _                  -> throwParseError "empty"
        State ((h,e):l) es | h == Start ty -> do let (l1, l2) = getConstructedEnd 0 (State l (es <> e))
                                                 put l2 >> return l1
                           | otherwise     -> throwParseError "not an expected container"


-- | run a function of the next elements of a container of specified type
onNextContainer :: Monoid e => ASN1ConstructionType -> ParseASN1 e a -> ParseASN1 e a
onNextContainer ty f = getNextContainer ty >>= either throwParseError return . runParseASN1_ f

-- | just like getNextContainer, except it doesn't throw an error if the container doesn't exists.
getNextContainerMaybe :: Monoid e => ASN1ConstructionType -> ParseASN1 e (Maybe [(ASN1, e)])
getNextContainerMaybe ty = do
    list <- get
    case list of
        State []        _                  -> return Nothing
        State ((h,e):l) es | h == Start ty -> do let (l1, l2) = getConstructedEnd 0 (State l (es <> e))
                                                 put l2 >> return (Just l1)
                           | otherwise     -> return Nothing

-- | just like onNextContainer, except it doesn't throw an error if the container doesn't exists.
onNextContainerMaybe :: Monoid e => ASN1ConstructionType -> ParseASN1 e a -> ParseASN1 e (Maybe a)
onNextContainerMaybe ty f = do
    n <- getNextContainerMaybe ty
    case n of
        Just l  -> either throwParseError (return . Just) $ runParseASN1_ f l
        Nothing -> return Nothing

-- | returns if there's more elements in the stream.
hasNext :: ParseASN1 e Bool
hasNext = do State l _ <- get; return . not . null $ l

-- | run a parser and return its result as well as all annotations that were used
withAnnotations :: Monoid e => ParseASN1 e a -> ParseASN1 e (a, e)
withAnnotations f = do
    State l es <- get
    case runP f (State l mempty) of
        Left err                -> throwParseError err
        Right (a, State l' es') -> do put (State l' (es <> es'))
                                      return (a, es')

getConstructedEnd :: Monoid e => Int -> State e -> ([(ASN1, e)], State e)
getConstructedEnd _ xs@(State [] _)                = ([], xs)
getConstructedEnd i (State (x@(Start _, e):xs) es) = let (yz, zs) = getConstructedEnd (i+1) (State xs (es <> e)) in (x:yz, zs)
getConstructedEnd i (State (x@(End _, e):xs) es)
    | i == 0    = ([], State xs (es <> e))
    | otherwise = let (ys, zs) = getConstructedEnd (i-1) (State xs (es <> e)) in (x:ys, zs)
getConstructedEnd i (State (x@(_, e):xs) es)       = let (ys, zs) = getConstructedEnd i (State xs (es <> e)) in (x:ys, zs)
