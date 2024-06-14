# vrnetlab / Juniper vJunos-router

This is the vrnetlab docker image for Juniper's vJunos-router. This is built from the vJunos-switch template.

## Building the docker image

Download the vJunos-router .qcow2 image from  <https://support.juniper.net/support/downloads/?p=vjunos-router>
and place it in this directory. After typing `make`, a new image will appear called `vrnetlab/vjunosrouter`.
Run `docker images` to confirm this.

The interface alias format supported on this image is `ge-0-0-X`, where X is the port number. The prefixes `et` and `te` can also be used interchangeably.

## System requirements

CPU: 4 cores
RAM: 5GB
DISK: ~4.5GB
