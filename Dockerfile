FROM node:13 as builder
ADD ./frontend /frontend
WORKDIR /frontend
RUN npm install && npm run build

FROM ubuntu:18.04

# Deps
RUN apt-get update
RUN apt-get install -y z3 libz3-dev ghc cabal-install python-pip python-virtualenv
RUN cabal update
RUN pip install ipaddr parsec textx==1.8.0 Flask

# Haskell libs
COPY ./lib/z3-haskell /FWSlib/z3-haskell
WORKDIR /FWSlib/z3-haskell
RUN cabal install --global
COPY ./lib/HaPy-haskell /FWSlib/HaPy-haskell
WORKDIR /FWSlib/HaPy-haskell
RUN cabal install --global
COPY ./FireWallSynthesizer.cabal /FWS/
WORKDIR /FWS
RUN cabal install --global --dependencies-only

# Python libs
COPY ./lib/HaPy-python /FWSlib/HaPy-python
WORKDIR /FWSlib/HaPy-python
RUN python setup.py install

# FWS Build
COPY . /FWS
WORKDIR /FWS
RUN ./update_libs.sh
RUN cabal install --global

# Copy frontend data
COPY --from=builder /frontend/dist /FWS/fwsynthesizer/web/static
# Install python fws
RUN python setup.py install

# Entrypoint
WORKDIR /mnt
ENTRYPOINT ["fws"]
