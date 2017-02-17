FROM luafan/webase

COPY cacert.* /root/
COPY config /root/config

COPY service /root/service
COPY database /root/database
COPY handle /root/handle
