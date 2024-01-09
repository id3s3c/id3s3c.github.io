---
title: Leveraging DevOps to Threat Hunt
layout: page
tags: devops
---

# Leveraging DevOps to Threat Hunt

So recently I started a freelance gig in devops, cause I always liked the sysadmin stuff and messing with devops tools like `ansible`, `salt` and `docker`, and would like to do two things: 

1. Use them in real world scenarios to build something big, and when to use each one.
2. Leverage them to increase the overall security view of networks/applications, including in software development life cycle.

*Disclaimer: I know that the buzzword is used to define *roles* instead of a culture change, with the objective to join `dev` and `ops` teams, but you know that this doesn't happen in most cases, so why not.*

And recently I was in charge of organizing a *not so running* security operation with a low budge (none), so I started studying the options and eventually stumbled into the [ELK Stack](https://www.elastic.co/pt/elastic-stack), and their parallel projects like [HELK](https://github.com/philhagen/sof-elk), [SOF](https://github.com/philhagen/sof-elk). Tried some of them and soon realized that a solid knowledge of the elastic stack was needed to understand and customize the installs. So I started the elastic learning journey.

Before staring I knew that I would need to understand/learn how to use the configuration management tools, and master the container technologies, and fortunately I got a free course of `docker` and `kubernetes` from my company, so I would like to share what I learned, my experiences and some tips.

## Docker and containers

So what exactly is a container? Well, [wikipedia](https://en.wikipedia.org/wiki/OS-level_virtualization) says that it is a kind of virtualization, where multiples **isolated** user spaces instances run. For those familiar with *nix stuff, think of a kind of `chroot ` or `jails` from bsd, adding `cgoups` for cpu/mem limiting, `ulimits`, `seccomp` and `selinux/apparmor`.

### So, how it is useful?

From a penetration tester perspective it can be very useful, as stated [ropnop in his blogpost](https://blog.ropnop.com/docker-for-pentesters/). You can test things in a quick, disposable and clean way, be compiling some exploit to a custom architecture, be creating shellcode without installing all the crapload of `msfvenom` stuff.

### Under the hood

So when you install docker in your system two main things happen: a daemon is needed to receive the calls from the client and interact with the kernel, and the `docker` client is installed.

One of the key components of docker are the images. They are like a cake recipe, where you define a logical sequence of instructions and commands to the ran to prepare and/or execute what it was designed for. You can build them using the `docker build` command, or you can `pull` them from public/private repositories called **registries**, ex: [Docker Hub](https://hub.docker.com/), Quay.io (from RH), [AWS ECR](https://aws.amazon.com/pt/ecr/).

So a example of execution flow would be:

1. Create a image/pull one from a repository
2. Build and run the container :)

Some interesting facts:

- Each container runs in a separated process in the host.
- Beware, by default it does not restrict the amount of RAM and CPU from the containers.
- To run the docker command you will need sudo privileges, or to be in the `docker` group. In other words, the `docker ` group has **sudo** privileges. 
- As far as I know the recipes (Dockerfile) used to built the images in docker hub are not known, **USE WITH CAUTION**.

I'm planning to publish a full series on how to do pratical threat hunting using the elk stack, sysmon, wazuh and stuff in a small lab, let's see how it goes.

## Cheat sheet

```bash
$ sudo docker pull

# Check running containers
$ sudo docker ps -a

# Check images
$ sudo docker images ls

# Interact with container
$ sudo docker exec -it <CONTAINER_ID> bash

# Binding port 80 from container to 8008 in host 
$ sudo docker run nginx -p 80:8008 -v /home/id3/html:/usr/share/html 

# Mapping a local volume into the container
$ sudo docker run nginx -v /home/id3/config:/etc/nginx
```

I'm planning to publish a full series on how to do pratical threat hunting using the elk stack, sysmon, wazuh and stuff in a small lab, let's see how it goes.