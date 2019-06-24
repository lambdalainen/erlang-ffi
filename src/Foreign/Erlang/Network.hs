-- |
-- Module      : Foreign.Erlang.Network
-- Copyright   : (c) Eric Sessoms, 2008
--               (c) Artúr Poór, 2015
-- License     : GPL3
-- 
-- Maintainer  : gombocarti@gmail.com
-- Stability   : experimental
-- Portability : portable
--
{-# LANGUAGE OverloadedStrings #-}

module Foreign.Erlang.Network (
  -- * Low-level communication with the Erlang Port-Mapper Daemon
    epmdGetNames
  , epmdGetPort
  , epmdGetPortR4
  
  , ErlRecv
  , ErlSend
  -- ** Representation of Erlang nodes
  , Name
  , HostName
  , Node(..)
  , erlConnect
  , toNetwork
  ) where

import Control.Exception        (assert, bracketOnError)
import Data.Binary.Get
import Data.Bits                ((.|.))
import Data.Char                (chr, ord)
import Data.Hash.MD5            (md5i, Str(..))
import Data.Int
import Data.List                (unfoldr)
import Data.Word
import Foreign.Erlang.Types
import Network.Socket
import System.Directory         (getHomeDirectory)
import System.FilePath          ((</>))
import System.IO
import System.Random            (randomIO)
import qualified Data.ByteString.Lazy.Char8 as B
import qualified Network.Socket.ByteString.Lazy as N
import Data.ByteString.Lazy.Builder
import Data.Monoid ((<>),mempty)

erlangVersion :: Int
erlangVersion = 5

erlangProtocolVersion :: Int
erlangProtocolVersion = 131

passThrough :: Char
passThrough = 'p'

flagPublished          =  0x01
flagAtomCache          =  0x02
flagExtendedReferences =  0x04
flagDistMonitor        =  0x08
flagFunTags            =  0x10
flagDistMonitorName    =  0x20
flagHiddenAtomCache    =  0x40
flagNewFunTags         =  0x80
flagExtendedPidsPorts  = 0x100
flagUTF8Atoms          = 0x10000

flagExtendedReferences :: Word32
flagExtendedPidsPorts  :: Word32
flagUTF8Atoms          :: Word32

getUserCookie :: IO String
getUserCookie = do
    home <- getHomeDirectory
    withFile (home </> ".erlang.cookie") ReadMode $ \h -> do
      eof <- hIsEOF h
      if eof
        then return ""
        else hGetLine h

toNetwork :: Int -> Integer -> [Word8]
toNetwork b n = reverse . take b $ unfoldr toNetwork' n ++ repeat 0
  where
    toNetwork' 0 = Nothing
    toNetwork' n = let (b, a) = n `divMod` 256 in Just (fromIntegral a, b)

erlDigest                  :: String -> Word32 -> [Word8]
erlDigest cookie challenge = let
    n = fromIntegral . md5i . Str $ cookie ++ show challenge
    in toNetwork 16 n

packn, packN :: Builder -> Builder
packn msg = putn (B.length msg') <> msg
    where msg' = toLazyByteString msg
packN msg = putN (B.length msg') <> msg
    where msg' = toLazyByteString msg

sendMessage :: (Builder -> Builder) -> (Builder -> IO ()) -> Builder -> IO ()
sendMessage pack out = out . pack

recvMessage :: Int64 -> (Int64 -> IO B.ByteString) -> IO B.ByteString
recvMessage hdrlen inf = ((fromIntegral . unpack hdrlen) <$> inf hdrlen) >>= inf
  where
    unpack 2 = runGet getn
    unpack 4 = runGet getN

type ErlSend = (Maybe ErlType, Maybe ErlType) -> IO ()
type ErlRecv = IO (Maybe ErlType, Maybe ErlType)
      
erlSend :: (Builder -> IO ()) -> ErlSend
erlSend send (Nothing, _)    = send . lazyByteString $ B.empty
erlSend send (Just ctl, msg) = send $
    tag passThrough <>
    putMsg ctl <>
    maybe mempty putMsg msg
  where
    putMsg msg = 
      putC erlangProtocolVersion <>
      putErl msg
      
erlRecv :: IO B.ByteString -> ErlRecv
erlRecv recv = do
    bytes <- recv
    return . flip runGet bytes $ do
      empty <- isEmpty
      if empty
        then return (Nothing, Nothing)
        else do
          pt <- getC
          assert (chr pt == passThrough) $ return ()
          ctl <- getMsg
          empty <- isEmpty
          if empty
            then return (Just ctl, Nothing)
            else case ctl of
                   ErlTuple (ErlInt n:_) | n `elem` [2, 6] -> do
                     msg <- getMsg
                     return (Just ctl, Just msg)
                   _ -> return (Just ctl, Nothing)
  where
    getMsg = do
      ver <- getC
      assert (ver == erlangProtocolVersion) $ getErl

-- | Name of an Erlang node.
type Name = String

-- | Representation of an Erlang node on the network.     
data Node 
    = Short Name         -- ^ Local Erlang node.
    | Long Name HostName -- ^ Remote Erlang node.
      deriving (Eq,Show)

instance Erlang Node where
    toErlang (Short name)   = ErlString name
    toErlang (Long name ip) = ErlString name
    fromErlang = undefined

withNode :: HostName -> ServiceName -> (Socket -> IO a) -> IO a
withNode epmd port = withSocketsDo . bracketOnError
    (resolve epmd port >>= open)
    close
          
erlConnect :: String -> Node -> IO (ErlSend, ErlRecv)
erlConnect self node = withSocketsDo $ do
    port <- epmdGetPort node
    withNode epmd port $ \sock -> do
        let out = sendMessage packn (N.sendAll sock . toLazyByteString)
        let inf = recvMessage 2 (recvN sock)
        handshake out inf self
        let out' = sendMessage packN (N.sendAll sock . toLazyByteString)
        let inf' = recvMessage 4 (recvN sock)
        return (erlSend out', erlRecv inf')
    where epmd = case node of
                   Short _    -> epmdLocal
                   Long  _ ip -> ip

handshake :: (Builder -> IO ()) -> IO B.ByteString -> String -> IO ()
handshake out inf self = do
    cookie <- getUserCookie
    sendName
    recvStatus
    challenge <- recvChallenge
    let reply = erlDigest cookie challenge
    challenge' <- fromIntegral <$> (randomIO :: IO Int)
    challengeReply reply challenge'
    recvChallengeAck cookie challenge'

  where
    sendName = out $
        tag 'n' <>
        putn erlangVersion <>
        putN (flagExtendedReferences .|. flagExtendedPidsPorts .|. flagUTF8Atoms .|. flagNewFunTags) <>
        putA self

    recvStatus = do
        msg <- inf
        assert ("sok" == B.unpack msg) $ return ()

    recvChallenge = do
        msg <- inf
        return . flip runGet msg $ do
            _tag <- getC
            _version <- getn 
            _flags <- getN
            challenge <- getWord32be
            return challenge

    challengeReply reply challenge = out $
        tag 'r' <>
        word32BE challenge <>
        puta reply

    recvChallengeAck cookie challenge = do
        let digest = erlDigest cookie challenge
        msg <- inf
        let reply = take 16 . tail . map (fromIntegral . ord) . B.unpack $ msg
        assert (digest == reply) $ return ()

epmdLocal :: HostName
epmdLocal = "127.0.0.1"
            
epmdPort :: ServiceName
epmdPort = "4369"

resolve host port = do
    let hints = defaultHints { addrSocketType = Stream }
    addr:_ <- getAddrInfo (Just hints) (Just host) (Just port)
    return addr

open addr = do
    sock <- socket (addrFamily addr) (addrSocketType addr) (addrProtocol addr)
    connect sock $ addrAddress addr
    -- putStrLn $ "### Connected to " <> show addr
    return sock

withEpmd :: String -> (Socket -> IO a) -> IO a
withEpmd epmd = withSocketsDo . bracketOnError
    (resolve epmd epmdPort >>= open)
    close

epmdAsk :: String -> String -> IO B.ByteString
epmdAsk epmd msg = withEpmd epmd $ \sock -> do
    let out = putn (length msg) <> putA msg
    N.sendAll sock $ toLazyByteString out
    recvAll sock

recvAll :: Socket -> IO B.ByteString
recvAll sock = (B.concat . reverse) <$> do_recv []
    where
    do_recv acc = do
        r <- N.recv sock 4096
        case r of
            "" -> return acc
            _  -> do_recv (r:acc)

recvN :: Socket -> Int64 -> IO B.ByteString
recvN sock n = (B.concat . reverse) <$> do_recv [] n
    where
    do_recv acc 0    = return acc
    do_recv acc left = do
        r <- N.recv sock left
        case r of
            "" -> error $ "recvN: Peer closed connection"
            _  -> do_recv (r:acc) (left - B.length r)

-- | Return the names and addresses of registered local Erlang nodes.
epmdGetNames :: IO [String]
epmdGetNames = do
    reply <- epmdAsk epmdLocal "n" -- 110 in ASCII
    let txt = runGet (getN >> fmap B.unpack getRemainingLazyByteString) reply
    return . lines $ txt

-- | Return the port address of a named Erlang node.
epmdGetPort :: Node -> IO ServiceName
epmdGetPort node = do
    reply <- epmdAsk epmd $ 'z' : nodeName
    return $ flip runGet reply $ do
        _   <- getC
        res <- getC
        if res == 0
          then show <$> getn
          else error $ "epmdGetPort: node not found: " ++ show node
    where
    (nodeName, epmd) = case node of
                           Short name    -> (name, epmdLocal)
                           Long  name ip -> (name, ip)

-- | Returns (port, nodeType, protocol, vsnMax, vsnMin, name, extra)
epmdGetPortR4 :: String -> String -> IO (Int, Int, Int, Int, Int, String, String)
epmdGetPortR4 epmd name = do
    reply <- epmdAsk epmd $ 'z' : name
    return $ flip runGet reply $ do
        _        <- getn
        port     <- getn
        nodeType <- getC
        protocol <- getC
        vsnMax   <- getn
        vsnMin   <- getn
        name     <- getn >>= getA
        extra    <- B.unpack <$> getRemainingLazyByteString
        return (port, nodeType, protocol, vsnMax, vsnMin, name, extra)
