FROM debian:12-slim

# Install dependencies
RUN apt-get update && apt-get install -y \
	bsdmainutils	\
	gcc	\
	git	\
	libbsd-dev	\
	make	\
	openssl

WORKDIR /opt
WORKDIR /workspace

# docker build . -t ft_ssl_des
# docker run -v "${PWD}":/workspace -it ft_ssl_des

# docker rm $(docker ps -qa --filter ancestor=ft_ssl_des)
# docker rmi ft_ssl_des