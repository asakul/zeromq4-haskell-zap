{-# LANGUAGE OverloadedStrings #-}
import Test.Tasty
import Test.Tasty.QuickCheck as QC
import Test.Tasty.HUnit

import Control.Concurrent
import System.ZMQ4.ZAP
import System.ZMQ4
import Data.Restricted

import Data.Text.Encoding

main :: IO ()
main = defaultMain tests

tests :: TestTree
tests = testGroup "Tests" [unitTests]

unitTests = testGroup "Unit tests" 
  [ testNullAuth, testPlainAuth, testCurveAuth ]

testNullAuth = testGroup "Testing NULL authentication mechanism" [ testNullAuthOk, testNullAuthDenied, testNullAuthDeniedIfInvalidDomain ]

testPlainAuth = testGroup "Testing Plain authentication mechanism" [ testPlainAuthOk, testPlainAuthInvalidPassword ]

testCurveAuth = testGroup "Testing Curve authentication mechanism" [ testCurveAuthOk, testCurveInvalidCertificate ]

testendpoint port = "tcp://127.0.0.1:" ++ show port

testNullAuthOk = testCase "Successful scenario" $ withContext (\ctx -> do
  withSocket ctx Rep (\server -> do
    setLinger (restrict 0) server
    withSocket ctx Req (\client -> do
      setLinger (restrict 0) client
      withZapHandler ctx (\zap -> do
        zapWhitelist zap "global" "127.0.0.1"
        setZapDomain "global" server
        bind server $ testendpoint 7737
        connect client $ testendpoint 7737
        threadDelay 100000

        send client [] $ encodeUtf8 "foobar"
        v <- receive server
        assertEqual "" (decodeUtf8 v) "foobar"))))
  
testNullAuthDenied = testCase "Blacklist scenario" $ do
  withContext (\ctx -> do
    withSocket ctx Rep (\server -> do
      setLinger (restrict 0) server
      withSocket ctx Req (\client -> do
        setLinger (restrict 0) client
        withZapHandler ctx (\zap -> do
          zapBlacklist zap "global" "127.0.0.1"
          setZapDomain "global" server
          bind server $ testendpoint 7738
          connect client $ testendpoint 7738

          send client [] $ encodeUtf8 "foobar"
          events <- poll 100 [Sock server [In] Nothing]
          assertBool "" (null . head $ events)
          ))))

testNullAuthDeniedIfInvalidDomain = testCase "Unknown domain scenario" $ do
  withContext (\ctx -> do
    withSocket ctx Rep (\server -> do
      setLinger (restrict 0) server
      withSocket ctx Req (\client -> do
        setLinger (restrict 0) client
        withZapHandler ctx (\zap -> do
          zapBlacklist zap "unknown_domain" "127.0.0.1"
          setZapDomain "global" server
          bind server $ testendpoint 7744
          connect client $ testendpoint 7744

          send client [] $ encodeUtf8 "foobar"
          events <- poll 100 [Sock server [In] Nothing]
          assertBool "" (null . head $ events)
          ))))
  
testPlainAuthOk = testCase "Successful scenario" $ withContext (\ctx -> do
  withSocket ctx Rep (\server -> do
    setLinger (restrict 0) server
    setZapDomain "global" server
    withSocket ctx Req (\client -> do
      setLinger (restrict 0) client
      withZapHandler ctx (\zap -> do
        zapSetPlainCredentialsFilename zap "global" "test/secret"
        setPlainServer True server
        setPlainUserName (restrict $ encodeUtf8 "testuser") client
        setPlainPassword (restrict $ encodeUtf8 "testpassword") client

        bind server $ testendpoint 7739
        connect client $ testendpoint 7739
        threadDelay 100000

        send client [] $ encodeUtf8 "foobar"
        v <- receive server
        assertEqual "" (decodeUtf8 v) "foobar"))))
  
testPlainAuthInvalidPassword = testCase "Invalid password, existing user" $ withContext (\ctx -> do
  withSocket ctx Rep (\server -> do
    setLinger (restrict 0) server
    setZapDomain "global" server
    withSocket ctx Req (\client -> do
      setLinger (restrict 0) client
      withZapHandler ctx (\zap -> do
        zapSetPlainCredentialsFilename zap "global" "test/secret"
        setPlainServer True server
        setPlainUserName (restrict $ encodeUtf8 "testuser") client
        setPlainPassword (restrict $ encodeUtf8 "invalid password") client

        bind server $ testendpoint 7740
        connect client $ testendpoint 7740

        send client [] $ encodeUtf8 "foobar"
        events <- poll 100 [Sock server [In] Nothing]
        assertBool "" (null . head $ events)
        ))))

testCurveAuthOk = testCase "Successful scenario" $ withContext (\ctx -> do
  withSocket ctx Rep (\server -> do
    setLinger (restrict 0) server
    setZapDomain "global" server
    serverCert <- generateCertificate
    setCurveServer True server
    zapApplyCertificate serverCert server

    withSocket ctx Req (\client -> do
      setLinger (restrict 0) client

      clientCert <- generateCertificate
      zapApplyCertificate clientCert client
      zapSetServerCertificate (withoutSecretKey serverCert) client

      withZapHandler ctx (\zap -> do
        zapAddClientCertificate zap "global" (withoutSecretKey clientCert)
        bind server $ testendpoint 7741
        connect client $ testendpoint 7741
        threadDelay 100000

        send client [] $ encodeUtf8 "foobar"
        v <- receive server
        assertEqual "" (decodeUtf8 v) "foobar"))))

testCurveInvalidCertificate = testCase "Invalid Client Pubkey" $ withContext (\ctx -> do
  withSocket ctx Rep (\server -> do
    setLinger (restrict 0) server
    setZapDomain "global" server
    serverCert <- generateCertificate
    setCurveServer True server
    zapApplyCertificate serverCert server

    withSocket ctx Req (\client -> do
      setLinger (restrict 0) client

      clientCert <- generateCertificate
      zapApplyCertificate clientCert client
      zapSetServerCertificate (withoutSecretKey serverCert) client

      withZapHandler ctx (\zap -> do
        bind server $ testendpoint 7742
        connect client $ testendpoint 7742
        threadDelay 100000

        send client [] $ encodeUtf8 "foobar"
        events <- poll 100 [Sock server [In] Nothing]
        assertBool "" (null . head $ events)))))
