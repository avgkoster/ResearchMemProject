cd /d "C:\Program Files\MongoDB\Server\5.0\bin"
mongo.exe --eval "db.getSiblingDB('volatility').createCollection(\"proccesses\")"

pause