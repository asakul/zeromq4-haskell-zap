
module Main (
  main
) where


import           Data.Monoid
import           Options.Applicative
import           System.ZMQ4.ZAP

data Params = Params {
  fullCertFile :: FilePath,
  pubKeyFile   :: FilePath
} deriving (Show, Eq)

paramsParser :: Parser Params
paramsParser = Params
  <$> strOption (long "cert-file" <> metavar "FILEPATH")
  <*> strOption (long "pub-file" <> metavar "FILEPATH")


main :: IO ()
main = do
  params <- execParser opts
  cert <- generateCertificate
  saveCertificateToFile (fullCertFile params) cert
  saveCertificateToFile (pubKeyFile params) (withoutSecretKey cert)

  where
    opts = info (helper <*> paramsParser)
      ( fullDesc <> header "zeromq4-haskell-zap certificate generator" )
