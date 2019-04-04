#!/bin/bash


GHC_VERSION=$(ghc --numeric-version)
BASE_VERSION=$(ghc-pkg latest base)

SED="sed -i"
if [ $(uname) == Darwin ]; then
    SED="sed -i ''"
fi

$SED "s#.*extra-lib-dir.*#  extra-lib-dirs: /usr/lib/ghc-${GHC_VERSION}/rts, /usr/lib/ghc/rts#" FireWallSynthesizer.cabal

if [ ${GHC_VERSION} \< "8.0" ]; then\
  $SED "s/.*extra-libraries.*/  extra-libraries: HSrts-ghc${GHC_VERSION}/" FireWallSynthesizer.cabal
else
  $SED "s/.*extra-libraries.*/  extra-libraries: HSrts-ghc${GHC_VERSION}, HS${BASE_VERSION}-ghc${GHC_VERSION}/" \
      FireWallSynthesizer.cabal
fi

