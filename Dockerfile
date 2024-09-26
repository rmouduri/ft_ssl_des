FROM debian:12-slim

# Install dependencies
RUN apt-get update && apt-get install -y \
	bsdmainutils	\
	git	\
	make	\
	gcc	\
	openssl

WORKDIR /opt
WORKDIR /workspace

# docker build . -t ft_ssl_des
# docker run -v "${PWD}":/workspace -it ft_ssl_des