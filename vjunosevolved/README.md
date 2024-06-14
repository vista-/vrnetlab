# vrnetlab / Juniper vJunosEvolved

This is the vrnetlab docker image for Juniper's vJunosEvolved.

> Available with [containerlab](https://containerlab.dev) as juniper_vjunosevolved.

## Building the docker image

Download the vJunosEvolved .qcow2 image from  <https://www.juniper.net/us/en/dm/vjunos-labs.html>
and place it in this directory. After typing `make`, a new image will appear called `vrnetlab/vjunosevolved`.
Run `docker images` to confirm this.

The interface alias format supported on this image is `ge-0-0-X`, where X is the port number. The prefixes `et` and `te` can also be used interchangeably.

## System requirements

CPU: 4 cores
RAM: 8GB
DISK: ~2.5GB
