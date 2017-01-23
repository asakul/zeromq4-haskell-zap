{-# LANGUAGE OverloadedStrings #-}

module System.ZMQ4.ZAP (
  startZapHandler,
  stopZapHandler,
  withZapHandler,
  zapWhitelist,
  zapBlacklist,
  zapSetWhitelist,
  zapSetBlacklist,
  zapSetPlainCredentialsFilename,
  setZapDomain

) where

import Control.Concurrent
import Control.Monad
import Control.Monad.Loops
import Control.Exception
import qualified Data.ByteString as B
import qualified Data.Text as T
import qualified Data.List as L
import Data.Text.Encoding
import Data.IORef
import Data.Maybe
import System.ZMQ4
import System.ZMQ4.Internal
import Data.List.NonEmpty
import qualified System.ZMQ4.Internal.Base as ZB
import System.IO
import qualified Data.Text.IO as TIO

data ZapParams = ZapParams {
  zpKill :: Bool,
  zpMv :: MVar (),
  zpIpWhitelist :: [T.Text],
  zpIpBlacklist :: [T.Text],
  zpPlainPasswordsFile :: Maybe FilePath
}

type Zap = (IORef ZapParams, ThreadId)

data ZapRequest = ZapRequest {
  zrqVersion :: T.Text,
  zrqRequestId :: B.ByteString,
  zrqDomain :: T.Text,
  zrqAddress :: T.Text,
  zrqIdentity :: B.ByteString,
  zrqMechanism :: SecurityMechanism,
  zrqCredentials :: [B.ByteString]
} deriving (Show, Eq)

setZapDomain :: T.Text -> Socket a -> IO ()
setZapDomain domain sock = setByteStringOpt sock ZB.zapDomain (encodeUtf8 domain)

startZapHandler :: Context -> IO Zap
startZapHandler ctx = do
  killmv <- newEmptyMVar
  paramsRef <- newIORef ZapParams {
    zpKill = False,
    zpMv = killmv,
    zpIpWhitelist = [],
    zpIpBlacklist = [],
    zpPlainPasswordsFile = Nothing}

  tid <- forkIO $ withSocket ctx Rep (\sock -> do
    bind sock "inproc://zeromq.zap.01"
    whileM_ (not . zpKill <$> readIORef paramsRef) $ do
      events <- poll 500 [Sock sock [In] Nothing]
      unless (L.null . L.head $ events) $ do
        msg <- parseMessage <$> receiveMulti sock
        params <- readIORef paramsRef
        case msg of
          Just m -> do
            response <- makeResponse m params
            sendMulti sock response
          Nothing -> sendMulti sock (make400Response B.empty "")
    putMVar killmv ())
  return (paramsRef, tid)

stopZapHandler :: Zap -> IO ()
stopZapHandler (params, tid) = do
  mv <- zpMv <$> readIORef params
  atomicModifyIORef' params (\p -> (p { zpKill = True }, ()) )
  void $ takeMVar mv

withZapHandler :: Context -> (Zap -> IO a) -> IO a
withZapHandler ctx action = bracket (startZapHandler ctx) stopZapHandler action

zapWhitelist :: Zap -> T.Text -> IO ()
zapWhitelist (paramsRef, _) newIp = atomicModifyIORef' paramsRef (\p -> (p { zpIpWhitelist = newIp : zpIpWhitelist p }, ())) 

zapBlacklist :: Zap -> T.Text -> IO ()
zapBlacklist (paramsRef, _) newIp = atomicModifyIORef' paramsRef (\p -> (p { zpIpBlacklist = newIp : zpIpBlacklist p }, ()))

zapSetWhitelist :: Zap -> [T.Text] -> IO ()
zapSetWhitelist (paramsRef, _) newList = atomicModifyIORef' paramsRef (\p -> (p { zpIpWhitelist = newList }, ())) 

zapSetBlacklist :: Zap -> [T.Text] -> IO ()
zapSetBlacklist (paramsRef, _) newList = atomicModifyIORef' paramsRef (\p -> (p { zpIpBlacklist = newList }, ()))

zapSetPlainCredentialsFilename :: Zap -> FilePath -> IO ()
zapSetPlainCredentialsFilename (paramsRef, _) filepath = atomicModifyIORef' paramsRef (\p -> (p { zpPlainPasswordsFile = Just filepath }, ()))

parseMessage :: [B.ByteString] -> Maybe ZapRequest
parseMessage (rVersion:rRqId:rDomain:rAddress:rIdentity:rMechanism:rCredentials) = 
  case parseMechanism rMechanism of
    Just m -> Just ZapRequest {
      zrqVersion = decodeUtf8 rVersion,
      zrqRequestId = rRqId,
      zrqDomain = decodeUtf8 rDomain,
      zrqAddress = decodeUtf8 rAddress,
      zrqIdentity = rIdentity,
      zrqMechanism = m,
      zrqCredentials = rCredentials     
    }
    Nothing -> Nothing
  where
    parseMechanism t
      | t == "NULL" = Just Null
      | t == "PLAIN" = Just Plain
      | t == "CURVE" = Just Curve
      | otherwise = Nothing

makeResponse :: ZapRequest -> ZapParams -> IO (NonEmpty B.ByteString)
makeResponse msg params =
  case zrqMechanism msg of
    Null -> makeResponseForNull
    Plain -> makeResponseForPlain
    Curve -> makeResponseForCurve
  where
    makeResponseForNull = return $ if listsAllow (zrqAddress msg)
      then make200Response (zrqRequestId msg) ""
      else make400Response (zrqRequestId msg) ""

    makeResponseForPlain = if not $ listsAllow (zrqAddress msg)
      then return $ make400Response (zrqRequestId msg) ""
      else case (zrqCredentials msg) of
        (username:password:_) -> do
          v <- validatePlainCredentials (decodeUtf8 username) (decodeUtf8 password)
          return $ if v
            then make200Response (zrqRequestId msg) ""
            else make400Response (zrqRequestId msg) ""
        _ -> return $ make400Response (zrqRequestId msg) ""

    validatePlainCredentials username suppliedPassword = do
      case zpPlainPasswordsFile params of
        Just filename -> do
          filecontents <- TIO.readFile filename
          case L.lookup username (credentialsListFrom filecontents) of
            Just correctPassword -> return $ suppliedPassword == correctPassword
            Nothing -> return False
        Nothing -> return False
    credentialsListFrom contents = mapMaybe credentialFromLine $ T.lines contents
    credentialFromLine t = case T.split (== '=') t of
      (un:pw:[]) -> Just (un, pw)
      _ -> Nothing
        
    makeResponseForCurve = undefined

    listsAllow address = if not . null $ whitelist
      then address `elem` whitelist
      else address `notElem` blacklist

    whitelist = zpIpWhitelist params
    blacklist = zpIpBlacklist params
    
make200Response rqid userId = encodeUtf8 "1.0" :| rqid : encodeUtf8 "200" : B.empty : encodeUtf8 userId : [B.empty]
make400Response rqid userId = encodeUtf8 "1.0" :| rqid : encodeUtf8 "400" : B.empty : encodeUtf8 userId : [B.empty]
    

