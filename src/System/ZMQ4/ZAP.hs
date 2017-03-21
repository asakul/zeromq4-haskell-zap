{-# LANGUAGE OverloadedStrings #-}

module System.ZMQ4.ZAP (
  CurveCertificate(..),
  startZapHandler,
  stopZapHandler,
  withZapHandler,
  zapWhitelist,
  zapBlacklist,
  zapSetWhitelist,
  zapSetBlacklist,
  zapSetPlainCredentialsFilename,
  zapApplyCertificate,
  zapSetServerCertificate,
  withoutSecretKey,
  generateCertificate,
  zapAddClientCertificate,
  setZapDomain,
  loadCertificateFromFile,
  saveCertificateToFile
) where

import Control.Concurrent
import Control.Monad
import Control.Monad.Loops
import Control.Exception
import Data.Aeson hiding (Null)
import qualified Data.ByteString as B
import qualified Data.ByteString.Lazy as BL
import qualified Data.ByteString.Base64 as B64
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
import System.Log
import System.Log.Logger

data CurveCertificate = CurveCertificate {
  ccPubKey :: B.ByteString,
  ccPrivKey :: Maybe B.ByteString
} deriving (Eq)

-- Meh
instance FromJSON CurveCertificate where
  parseJSON = withObject "object" (\obj -> do
    pub <- obj .: "public_key"
    case B64.decode . encodeUtf8 $ pub of
      Right pubKey -> do 
        priv <- obj .:? "secret_key"
        case priv of
          Just p -> case B64.decode . encodeUtf8 $ p of
            Right privKey -> return $ CurveCertificate pubKey (Just privKey)
            _ -> fail "CurveCertificate"
          Nothing -> return $ CurveCertificate pubKey Nothing
      _ -> fail "CurveCertificate")

instance ToJSON CurveCertificate where
  toJSON cert = object $ ( "public_key" .= (decodeUtf8 . B64.encode $ ccPubKey cert) ) : case ccPrivKey cert of
    Just privKey -> [ "secret_key" .= (decodeUtf8 . B64.encode $ privKey) ]
    Nothing -> []

instance Show CurveCertificate where
  show cert = "CurveCertificate { ccPubKey = " ++ (show . ccPubKey) cert ++ ", ccPrivKey = " ++ privKey ++ " }"
    where
      privKey = case ccPrivKey cert of
        Just key -> "***"
        Nothing -> "Nothing"

reallyShow :: CurveCertificate -> String
reallyShow cert = "CurveCertificate { ccPubKey = " ++ (show . ccPubKey) cert ++ ", ccPrivKey = " ++ (show . ccPrivKey) cert ++ " }"

data ZapParams = ZapParams {
  zpMv :: MVar (),
  zpIpWhitelist :: [T.Text],
  zpIpBlacklist :: [T.Text],
  zpPlainPasswordsFile :: Maybe FilePath,
  zpCurveCertificates :: [CurveCertificate]
}

type Zap = (IORef ZapParams, Context, ThreadId)

data ZapRequest = ZapRequest {
  zrqVersion :: T.Text,
  zrqRequestId :: B.ByteString,
  zrqDomain :: T.Text,
  zrqAddress :: T.Text,
  zrqIdentity :: B.ByteString,
  zrqMechanism :: SecurityMechanism,
  zrqCredentials :: [B.ByteString]
} deriving (Show, Eq)

zapSignalEndpoint = "inproc://zeromq.zap.01-signal"

setZapDomain :: T.Text -> Socket a -> IO ()
setZapDomain domain sock = setByteStringOpt sock ZB.zapDomain (encodeUtf8 domain)

startZapHandler :: Context -> IO Zap
startZapHandler ctx = do
  killmv <- newEmptyMVar
  paramsRef <- newIORef ZapParams {
    zpMv = killmv,
    zpIpWhitelist = [],
    zpIpBlacklist = [],
    zpPlainPasswordsFile = Nothing,
    zpCurveCertificates = []}

  tid <- forkIO $ withSocket ctx Rep (\sock ->
    withSocket ctx Pull (\signalSock -> do
      bind sock "inproc://zeromq.zap.01"
      bind signalSock zapSignalEndpoint
      killFlag <- newIORef False
      whileM_ (not <$> readIORef killFlag) $ do
        events <- poll 1000 [Sock sock [In] Nothing, Sock signalSock [In] Nothing]
        unless (L.null . L.head . L.tail $ events) $ do
          writeIORef killFlag True
        unless (L.null . L.head $ events) $ do
          msg <- parseMessage <$> receiveMulti sock
          debugM "ZAP" $ "Request: " ++ show msg
          params <- readIORef paramsRef
          case msg of
            Just m -> do
              response <- makeResponse m params
              debugM "ZAP" $ "Response: " ++ show response
              sendMulti sock response
            Nothing -> sendMulti sock (make400Response B.empty "")
      putMVar killmv ()))
  return (paramsRef, ctx, tid)

stopZapHandler :: Zap -> IO ()
stopZapHandler (params, ctx, tid) = do
  mv <- zpMv <$> readIORef params
  withSocket ctx Push (\signalSock -> do
    connect signalSock zapSignalEndpoint
    send signalSock [] B.empty)
  void $ takeMVar mv

withZapHandler :: Context -> (Zap -> IO a) -> IO a
withZapHandler ctx action = bracket (startZapHandler ctx) stopZapHandler action

zapWhitelist :: Zap -> T.Text -> IO ()
zapWhitelist (paramsRef, _ ,_) newIp = atomicModifyIORef' paramsRef (\p -> (p { zpIpWhitelist = newIp : zpIpWhitelist p }, ())) 

zapBlacklist :: Zap -> T.Text -> IO ()
zapBlacklist (paramsRef, _, _) newIp = atomicModifyIORef' paramsRef (\p -> (p { zpIpBlacklist = newIp : zpIpBlacklist p }, ()))

zapSetWhitelist :: Zap -> [T.Text] -> IO ()
zapSetWhitelist (paramsRef, _, _) newList = atomicModifyIORef' paramsRef (\p -> (p { zpIpWhitelist = newList }, ())) 

zapSetBlacklist :: Zap -> [T.Text] -> IO ()
zapSetBlacklist (paramsRef, _, _) newList = atomicModifyIORef' paramsRef (\p -> (p { zpIpBlacklist = newList }, ()))

zapSetPlainCredentialsFilename :: Zap -> FilePath -> IO ()
zapSetPlainCredentialsFilename (paramsRef, _, _) filepath = atomicModifyIORef' paramsRef (\p -> (p { zpPlainPasswordsFile = Just filepath }, ()))

zapApplyCertificate :: CurveCertificate -> Socket a -> IO ()
zapApplyCertificate cert sock = do
  setCurvePublicKey BinaryFormat (restrict $ ccPubKey cert) sock
  case ccPrivKey cert of
    Just key -> setCurveSecretKey BinaryFormat (restrict $ key) sock
    Nothing -> return ()

zapSetServerCertificate :: CurveCertificate -> Socket a -> IO ()
zapSetServerCertificate cert sock = setCurveServerKey BinaryFormat (restrict $ ccPubKey cert) sock

withoutSecretKey :: CurveCertificate -> CurveCertificate
withoutSecretKey cert = cert { ccPrivKey = Nothing }

generateCertificate :: IO CurveCertificate
generateCertificate = do
  (rPub, rSec) <- curveKeyPair
  dPub <- z85Decode rPub
  dSec <- z85Decode rSec
  return CurveCertificate { ccPubKey = dPub, ccPrivKey = Just dSec }

zapAddClientCertificate :: Zap -> CurveCertificate -> IO ()
zapAddClientCertificate (paramsRef, _, _) cert = atomicModifyIORef' paramsRef (\p -> (p { zpCurveCertificates = cert : zpCurveCertificates p }, ()))

loadCertificateFromFile :: FilePath -> IO (Either String CurveCertificate)
loadCertificateFromFile fpath = eitherDecode . BL.fromStrict <$> B.readFile fpath

saveCertificateToFile :: FilePath -> CurveCertificate -> IO ()
saveCertificateToFile fpath cert = withFile fpath WriteMode (\h -> B.hPut h $ BL.toStrict $ encode cert)

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
        
    makeResponseForCurve = if not $ listsAllow (zrqAddress msg)
      then return $ make400Response (zrqRequestId msg) ""
      else case (zrqCredentials msg) of
        (pubkey:_) -> do
          return $ if validateCurveCertificate pubkey
            then make200Response (zrqRequestId msg) ""
            else make400Response (zrqRequestId msg) ""
        _ -> return $ make400Response (zrqRequestId msg) ""

    validateCurveCertificate pubkey = isJust $ L.find (\x -> ccPubKey x == pubkey) (zpCurveCertificates params)

    listsAllow address = if not . null $ whitelist
      then address `elem` whitelist
      else address `notElem` blacklist

    whitelist = zpIpWhitelist params
    blacklist = zpIpBlacklist params
    
make200Response rqid userId = encodeUtf8 "1.0" :| rqid : encodeUtf8 "200" : B.empty : encodeUtf8 userId : [B.empty]
make400Response rqid userId = encodeUtf8 "1.0" :| rqid : encodeUtf8 "400" : B.empty : encodeUtf8 userId : [B.empty]
    

