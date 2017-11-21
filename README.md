Simple ZeroMQ Authentication Protocol (ZAP) implementation for zeromq4-haskell.

Example of usage with NULL authentication scheme:

```haskell
withContext (\ctx -> do
  withSocket ctx Rep (\server -> do
    withSocket ctx Req (\client -> do
      withZapHandler ctx (\zap -> do
        zapWhitelist zap "global" "127.0.0.1"
        setZapDomain "global" server
        bind server "tcp://127.0.0.1:7737"
        connect client "tcp://127.0.0.1:7737"

        send client [] $ encodeUtf8 "foobar"
        v <- receive server
        print v))))
```
 
Here, we create two sockets - server and client and then add localhost in the whitelist.

More examples can be found in test/Spec.hs

