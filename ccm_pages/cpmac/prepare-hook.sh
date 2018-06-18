#!/bin/bash

rm -f node_modules/long/dist/long.min.js.gz
rm -f platforms/android/src/main/assets/app/tns_modules/long/dist/long.min.js.gz

rm -R node_modules/nativescript-zxing/platforms/android/

cp brorand-fix/index.js node_modules/brorand/index.js
