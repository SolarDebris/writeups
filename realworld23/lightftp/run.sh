#!/bin/sh
docker build . -t lightftp
docker run --network host -ti lightftp 
