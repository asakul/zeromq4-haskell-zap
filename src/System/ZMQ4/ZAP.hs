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

import           Control.Concurrent
import           Control.Exception
import           Control.Monad
import           Control.Monad.Loops

import           Data.Aeson                hiding (Null)
import qualified Data.ByteString           as B
import qualified Data.ByteString.Base64    as B64
import qualified Data.ByteString.Lazy      as BL
import           Data.IORef
import qualified Data.List                 as L
import           Data.List.NonEmpty
import qualified Data.Map                  as M
import           Data.Maybe
import qualified Data.Text                 as T
import           Data.Text.Encoding
import qualified Data.Text.IO              as TIO

import           System.IO
import           System.Log
import           System.Log.Logger
import           System.ZMQ4
import           System.ZMQ4.Internal
import qualified System.ZMQ4.Internal.Base as ZB

data CurveCertificate = CurveCertificate {
  ccPubKey  :: B.ByteString,
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
            _             -> fail "CurveCertificate"
          Nothing -> return $ CurveCertificate pubKey Nothing
      _ -> fail "CurveCertificate")

instance ToJSON CurveCertificate where
  toJSON cert = object $ ( "public_key" .= (decodeUtf8 . B64.encode $ ccPubKey cert) ) : case ccPrivKey cert of
    Just privKey -> [ "secret_key" .= (decodeUtf8 . B64.encode $ privKey) ]
    Nothing      -> []

instance Show CurveCertificate where
  show cert = "CurveCertificate { ccPubKey = " ++ (show . ccPubKey) cert ++ ", ccPrivKey = " ++ privKey ++ " }"
    where
      privKey = case ccPrivKey cert of
        Just key -> "***"
        Nothing  -> "Nothing"

reallyShow :: CurveCertificate -> String
reallyShow cert = "CurveCertificate { ccPubKey = " ++ (show . ccPubKey) cert ++ ", ccPrivKey = " ++ (show . ccPrivKey) cert ++ " }"

type DomainId = T.Text

data ZapParams = ZapParams {
  zpMv           :: MVar (),
  zpDomainParams :: M.Map DomainId ZapDomainParams
}

data ZapDomainParams = ZapDomainParams {
  zpIpWhitelist        :: [T.Text],
  zpIpBlacklist        :: [T.Text],
  zpPlainPasswordsFile :: Maybe FilePath,
  zpCurveCertificates  :: [CurveCertificate]
}

defaultDomainParams = ZapDomainParams {
  zpIpWhitelist = [],
  zpIpBlacklist = [],
  zpPlainPasswordsFile = Nothing,
  zpCurveCertificates = []
}

type Zap = (IORef ZapParams, Context, ThreadId)

data ZapRequest = ZapRequest {
  zrqVersion     :: T.Text,
  zrqRequestId   :: B.ByteString,
  zrqDomain      :: DomainId,
  zrqAddress     :: T.Text,
  zrqIdentity    :: B.ByteString,
  zrqMechanism   :: SecurityMechanism,
  zrqCredentials :: [B.ByteString]
} deriving (Show, Eq)

zapSignalEndpoint = "inproc://zeromq.zap.01-signal"
zapEndpoint = "inproc://zeromq.zap.01"

setZapDomain :: DomainId -> Socket a -> IO ()
setZapDomain domain sock = setByteStringOpt sock ZB.zapDomain (encodeUtf8 domain)

startZapHandler :: Context -> IO Zap
startZapHandler ctx = do
  killmv <- newEmptyMVar
  paramsRef <- newIORef ZapParams {
    zpMv = killmv,
    zpDomainParams = M.empty }

  tid <- forkIO $ withSocket ctx Rep (\sock ->
    withSocket ctx Pull (\signalSock -> do
      bind sock zapEndpoint
      bind signalSock zapSignalEndpoint
      killFlag <- newIORef False
      whileM_ (not <$> readIORef killFlag) $ do
        events <- poll 1000 [Sock sock [In] Nothing, Sock signalSock [In] Nothing]
        unless (L.null . L.head . L.tail $ events) $ writeIORef killFlag True
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

withDomainEntry :: Zap -> DomainId -> (ZapDomainParams -> ZapDomainParams) -> IO ()
withDomainEntry (paramsRef, _, _)  domain f = atomicModifyIORef' paramsRef (\p -> (p { zpDomainParams = M.alter applyF domain (zpDomainParams p) }, ()))
  where
    applyF x = case x of
      Just params -> Just $ f params
      Nothing     -> Just $ f defaultDomainParams

zapWhitelist :: Zap -> DomainId -> T.Text -> IO ()
zapWhitelist zap domain newIp = withDomainEntry zap domain (\params ->
  params { zpIpWhitelist = newIp : zpIpWhitelist params } )

zapBlacklist :: Zap -> DomainId -> T.Text -> IO ()
zapBlacklist zap domain newIp = withDomainEntry zap domain (\params ->
  params { zpIpBlacklist = newIp : zpIpBlacklist params } )

zapSetWhitelist :: Zap -> DomainId -> [T.Text] -> IO ()
zapSetWhitelist zap domain newList = withDomainEntry zap domain (\params ->
  params { zpIpWhitelist = newList } )

zapSetBlacklist :: Zap -> DomainId -> [T.Text] -> IO ()
zapSetBlacklist zap domain newList = withDomainEntry zap domain (\params ->
  params { zpIpBlacklist = newList } )

zapSetPlainCredentialsFilename :: Zap -> DomainId -> FilePath -> IO ()
zapSetPlainCredentialsFilename zap domain filepath = withDomainEntry zap domain (\params -> params { zpPlainPasswordsFile = Just filepath } )

zapApplyCertificate :: CurveCertificate -> Socket a -> IO ()
zapApplyCertificate cert sock = do
  setCurvePublicKey BinaryFormat (restrict $ ccPubKey cert) sock
  case ccPrivKey cert of
    Just key -> setCurveSecretKey BinaryFormat (restrict $ key) sock
    Nothing  -> return ()

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

zapAddClientCertificate :: Zap -> DomainId -> CurveCertificate -> IO ()
zapAddClientCertificate zap domain cert = withDomainEntry zap domain (\params ->
  params { zpCurveCertificates = cert : (zpCurveCertificates params) } )

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
makeResponse msg params = case M.lookup (zrqDomain msg) (zpDomainParams params) of
  Just domainParams ->
    case zrqMechanism msg of
      Null  -> makeResponseForNull domainParams
      Plain -> makeResponseForPlain domainParams
      Curve -> makeResponseForCurve domainParams
  Nothing -> return $ make400Response (zrqRequestId msg) ""
  where
    makeResponseForNull domainParams = return $ if listsAllow (zrqAddress msg) domainParams
      then make200Response (zrqRequestId msg) ""
      else make400Response (zrqRequestId msg) ""

    makeResponseForPlain domainParams = if not $ listsAllow (zrqAddress msg) domainParams
      then return $ make400Response (zrqRequestId msg) ""
      else case (zrqCredentials msg) of
        (username:password:_) -> do
          v <- validatePlainCredentials (decodeUtf8 username) (decodeUtf8 password) domainParams
          return $ if v
            then make200Response (zrqRequestId msg) ""
            else make400Response (zrqRequestId msg) ""
        _ -> return $ make400Response (zrqRequestId msg) ""

    validatePlainCredentials username suppliedPassword domainParams = do
      case zpPlainPasswordsFile domainParams of
        Just filename -> do
          filecontents <- TIO.readFile filename
          case L.lookup username (credentialsListFrom filecontents) of
            Just correctPassword -> return $ suppliedPassword == correctPassword
            Nothing -> return False
        Nothing -> return False

    credentialsListFrom contents = mapMaybe credentialFromLine $ T.lines contents
    credentialFromLine t = case T.split (== '=') t of
      (un:pw:[]) -> Just (un, pw)
      _          -> Nothing

    makeResponseForCurve domainParams = if not $ listsAllow (zrqAddress msg) domainParams
      then return $ make400Response (zrqRequestId msg) ""
      else case (zrqCredentials msg) of
        (pubkey:_) -> do
          return $ if validateCurveCertificate pubkey domainParams
            then make200Response (zrqRequestId msg) ""
            else make400Response (zrqRequestId msg) ""
        _ -> return $ make400Response (zrqRequestId msg) ""

    validateCurveCertificate pubkey domainParams = isJust $ L.find (\x -> ccPubKey x == pubkey) (zpCurveCertificates domainParams)

    listsAllow address domainParams = if not . null $ (zpIpWhitelist domainParams)
      then address `elem` (zpIpWhitelist domainParams)
      else address `notElem` (zpIpBlacklist domainParams)

make200Response rqid userId = encodeUtf8 "1.0" :| rqid : encodeUtf8 "200" : B.empty : encodeUtf8 userId : [B.empty]
make400Response rqid userId = encodeUtf8 "1.0" :| rqid : encodeUtf8 "400" : B.empty : encodeUtf8 userId : [B.empty]


