{-# LANGUAGE OverloadedStrings #-}
import Test.Tasty
import Test.Tasty.QuickCheck as QC
import Test.Tasty.HUnit

import System.ZMQ4.ZAP
import System.ZMQ4

import Data.Text.Encoding

main :: IO ()
main = defaultMain tests

tests :: TestTree
tests = testGroup "Tests" [unitTests]

unitTests = testGroup "Unit tests" 
  [ testNullAuth ]

testNullAuth = testGroup "Testing NULL authentication mechanism" [ testNullAuthOk, testNullAuthDenied ]

testendpoint port = "tcp://127.0.0.1:" ++ show port

testNullAuthOk = testCase "Successful scenario" $ withContext (\ctx -> do
  withZapHandler ctx (\zap -> do
    zapWhitelist zap "127.0.0.1"
    withSocket ctx Rep (\server -> do
      withSocket ctx Req (\client -> do
        setZapDomain "global" server
        bind server $ testendpoint 7737
        connect client $ testendpoint 7737

        send client [] $ encodeUtf8 "foobar"
        v <- receive server
        assertEqual "" (decodeUtf8 v) "foobar"))))
  
testNullAuthDenied = testCase "Blacklist scenario" $ withContext (\ctx -> do
  withZapHandler ctx (\zap -> do
    zapBlacklist zap "127.0.0.1"
    withSocket ctx Rep (\server ->
      withSocket ctx Req (\client -> do
        setZapDomain "global" server
        bind server $ testendpoint 7738
        connect client $ testendpoint 7738

        send client [] $ encodeUtf8 "foobar"
        events <- poll 100 [Sock server [In] Nothing]
        assertBool "" (null . head $ events)))))
  
