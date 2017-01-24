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
  [ testNullAuth, testPlainAuth ]

testNullAuth = testGroup "Testing NULL authentication mechanism" [ testNullAuthOk, testNullAuthDenied ]

testPlainAuth = testGroup "Testing Plain authentication mechanism" [ testPlainAuthOk, testPlainAuthInvalidPassword ]

testendpoint port = "tcp://127.0.0.1:" ++ show port

testNullAuthOk = testCase "Successful scenario" $ withContext (\ctx -> do
  withSocket ctx Rep (\server -> do
    setLinger (restrict 0) server
    withSocket ctx Req (\client -> do
      setLinger (restrict 0) client
      withZapHandler ctx (\zap -> do
        zapWhitelist zap "127.0.0.1"
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
          zapBlacklist zap "127.0.0.1"
          setZapDomain "global" server
          bind server $ testendpoint 7738
          connect client $ testendpoint 7738

          send client [] $ encodeUtf8 "foobar"
          events <- poll 100 [Sock server [In] Nothing]
          assertBool "" (null . head $ events)
          ))))
  
testPlainAuthOk = testCase "Successful scenario" $ withContext (\ctx -> do
  withSocket ctx Rep (\server -> do
    setLinger (restrict 0) server
    withSocket ctx Req (\client -> do
      setLinger (restrict 0) client
      withZapHandler ctx (\zap -> do
        zapSetPlainCredentialsFilename zap "test/secret"
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
    withSocket ctx Req (\client -> do
      setLinger (restrict 0) client
      withZapHandler ctx (\zap -> do
        zapSetPlainCredentialsFilename zap "test/secret"
        setPlainServer True server
        setPlainUserName (restrict $ encodeUtf8 "testuser") client
        setPlainPassword (restrict $ encodeUtf8 "invalid password") client

        bind server $ testendpoint 7740
        connect client $ testendpoint 7740

        send client [] $ encodeUtf8 "foobar"
        events <- poll 100 [Sock server [In] Nothing]
        assertBool "" (null . head $ events)))))
