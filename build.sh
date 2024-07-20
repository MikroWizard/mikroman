#!/bin/sh
# run in dev mode

sudo docker build --rm --build-arg BUILDMODE=production -t mikroman .

