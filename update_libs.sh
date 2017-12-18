#!/bin/bash


GHC_VERSION=$(ghc --numeric-version)
BASE_VERSION=$(ghc-pkg latest base)

SED="sed -i"
if [ $(uname) == Darwin ]; then
    SED="sed -i ''"
fi

if [ ${GHC_VERSION} \< "8.0" ]; then\
  $SED "s/.*extra-libraries.*/  extra-libraries: HSrts-ghc${GHC_VERSION}/" FireWallSynthesizer.cabal
else
  $SED "s/.*extra-libraries.*/  extra-libraries: HSrts-ghc${GHC_VERSION}, HS${BASE_VERSION}-ghc${GHC_VERSION}/" \
      FireWallSynthesizer.cabal
fi

