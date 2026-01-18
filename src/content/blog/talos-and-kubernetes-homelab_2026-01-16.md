---
layout: post
pubDate: 2026-01-17
postType: Blog
heroImage: ../../../assets/posts/talos-homelab/banner.png
title: "Talos - Homelab"
date: Thu Jan 15 09:10:50 PM MST 2026
description: Discussing the setup of a k8s lab
# osType: Linux 
# difficulty: Medium
scenario: 
tags:
  - Instructional
  - Kubernetes
  - Talos
  - FluxCD
---


## Overview

I recently bought a [Beelink MiniPC](https://www.amazon.com/dp/B08PBGC763?ref=ppx_pop_dt_b_product_details&th=1) this little guy was helpful because I finally got to try out `Proxmox` a virtualization platform and what I wanted to do was setup my first actual kubernetes cluster. I've done it locally with minikube before, but you lose important context of actually using kubernetes, including scheduling, networking, storage and failure modes. You need separate nodes so that way it can delegate services to them and if a node goes down it can reschedule the workload rather than everything failing because that machine failed. Of course, using proxmox doesn't actually solve all of this because it abstracts the nodes across VM's but you're still on a single host and the other thing is scale and having another computer hosting proxmox would be the most ideal way to populate it, but this is just a start.

So to properly get a cluster up, I went about using an immutable OS that is specifically built for kubernetes: Talos. And to maintain the cluster's services I went with FluxCD utilizing GitOps. FluxCD I overcomplicated quite initially, but it's really a wonderfully simple and elegant solution once you 'get it'.  But to boot up your first cluster, you want a few things:
- Certificate Manager : [cert-manager](https://cert-manager.io/)
- Storage Solution : [Longhorn](https://longhorn.io/)
- Load Balancer : [MetalLLB](https://metallb.io/)
- Ingress Controller : [Traefik](https://traefik.io/)
- GitOps Controller : [FluxCD](https://fluxcd.io)
- Secrets Manager : [Bitwarden](https://bitwarden.com)

And orchestrating them all correctly can be quite a pain. So let's see if we can overcome some yaml and walk through most of this because I struggled more than I should have doing this.

## Bootstrapping

First we want to get an idea of the directory structure we'll be using
I went with something like this:
```
.
├── apps
│   ├── actual_budget
│   └── bloodhound
├── clusters
│   └── hl-cluster1
│       └── flux-system
├── external_services
│   └── home-assistant
└── infrastructure
    ├── controllers
    │   ├── cert-manager
    │   │   └── bitwarden
    │   ├── longhorn
    │   ├── metallb
    │   │   └── namespace
    │   └── traefik
    └── resources
        ├── controller-resources
        └── metallb-resources
```
The `clusters` directory will get made with fluxCD doing the bootstrapping.
The rest are up to you, but I tried to make it sensible to follow, where infra has all the services and resources, and any specific one-off dependency a service needs I keep it in the same folder. Which is why you see a bitwarden folder under the cert-manager folder; it needs DNS provider credentials in order to complete ACME challenges. We could just create the secret manually, but it's good practice, to manage it declaritively.


Then you can make your initial repo, and have flux bootstrap it.
```bash
mkdir -p my_homelab && cd my_homelab
flux bootstrap git --url=$GIT_REPO --private-key-file=$PATH_TO_SSH_KEY --path=clusters/hl-cluster
```

You'll end up having the new path in your directory. And inside the hl-cluster directory, we'll be able to put some FluxCD orchestration YAML's. These are important because Flux will try and just deploy everything all at once, if they're not there and when dealing with infrastructure, certain things need to be deployed in the correct order. I ended up using this:

1. Load Balancer
2. Load Balancer Configurations
3. Infrastructure
4. Infrastructure Configurations
5. Apps & Other Services

I chose this layout because the load balancer needs to be present before any `Service` objects of type `LoadBalancer` are created (which would be Traefik in our case). And all the other core infrastructure is needed for the applications and other services.

## Yamling

Before we start working this, we should have a general guideline about how sensibly view everything going on, because it's very easy to get lost in the sauce.

Flux kustomization / ordering.
```yaml
apiVersion: kustomize.toolkit.fluxcd.io/v1
kind: Kustomization
metadata:
  name: <Ordering Name>
  namespace: flux-system
spec:
  sourceRef:
    kind: GitRepository
    name: flux-system
  path: <Path from the directory root to your desired deployment>
  prune: true
  interval: 10m
  wait: true
  dependsOn:
    - name: <What order this depends on>

```

It's not necessary, but I ended up using a "step" or "segment" like ordering to keep things easy to follow. So if you have to inevitably run `flux get kustomizations` for some troubleshooting, you'll immediately see which step it failed at. The names are for pure readability rather than flux actually following them. Whatever you call them Flux will follow the `dependsOn` chain.
```
00-infra-loadbalancer-namespace
01-infra-loadbalancer
02-infra-loadbalancer-resources
03-infra-controllers
04-infra-controllers-configs
05-apps
05-external-services
flux-system
```

And in general each folder will share a similar structure:

```

k8s-helmrelease.yaml
k8s-helmrepo.yaml
k8s-namespace.yaml
kustomization.yaml
```

Helmreleases could create the namespace, but you can't guarantee the necessary labels and annotations for privileged pods (necessary for Talos) are there early enough, unless you manage the namespace yourself.  So it's best to to keep the same scheme for everything.


And they in general look like this:

```yaml
# Kustomization.yaml
apiVersion: kustomize.config.k8s.io/v1beta1
kind: Kustomization
resources:
  - namespace.yaml
  - helmrepo.yaml
  - helmrelease.yaml
```
The `kustomization.yaml` is specifically used when we point flux to deploy a folder. It looks for a kustomization.yaml to then apply everything in it.

```yaml
#namespace.yaml
apiVersion: v1
kind: Namespace
metadata:
  name: <Actual Name of the namespace>
  labels:
    name: <Optional label for grouping>
```

```yaml
# helmrepo.yaml
apiVersion: source.toolkit.fluxcd.io/v1
kind: HelmRepository
metadata:
  name: <Name of HelmRepo>
  namespace: flux-system
spec:
  interval: 1h
  url: <Url of helmrepo> 
  timeout: 5m

```

To typically validate these you'd run:
```bash
helm repo add traefik https://traefik.github.io/charts

helm search repo traefik
NAME                	CHART VERSION	APP VERSION	DESCRIPTION
traefik/traefik     	37.2.0       	v3.5.3     	A Traefik based Kubernetes ingress controller
traefik/traefik-crds	1.11.1       	           	A Traefik based Kubernetes ingress controller
traefik/traefik-hub 	4.2.0        	v2.11.0    	Traefik Hub Ingress Controller
traefik/traefik-mesh	4.1.1        	v1.4.8     	Traefik Mesh - Simpler Service Mesh
traefik/traefikee   	4.2.5        	v2.12.5    	Traefik Enterprise is a unified cloud-native ne...
traefik/maesh       	2.1.2        	v1.3.2     	Maesh - Simpler Service Mesh

```

That will list the chart versions for reference later in the helmrelease.

```yaml
# helmrelease.yaml
apiVersion: helm.toolkit.fluxcd.io/v2
kind: HelmRelease
metadata:
  name: <Name of desired helmrelease object>
  namespace: flux-system
spec:
  interval: 10m
  targetNamespace: <name-space for deployed chart>
  chart:
    spec:
      chart: <Name of chart must exist in the actual helm-repo from helm-repo search>
      version: "v37.2.0" # Specify the version
      sourceRef:
        kind: HelmRepository
        name: <Must match the label we created in helmrepo.yaml>
        namespace: flux-system
  install:
    createNamespace: true
    remediation:
      retries: 3
  values:
        # These are all optional values you can use for helm charts, this is from traefik
    entrypoints:
      web:
        address: ":80"
        http:
          redirections:
            entryPoint:
              to: websecure
              scheme: https
              permanent: true
```

## Gotchas

Along the way we'll encounter some rather pesky things. Here's some of them.
### MetalLB
I mentioned this earlier, but it needs to be deployed before any service of `LoadBalancer` which Traefik will be and also due to MetalLB requiring privileged networking capabilities and Talos enforcing strict pod security, we have to ensure the namespace is created before anything else.

### Longhorn
Longhorn as a storage solution is wonderful, it will ensure pods maintain persistence data and even have incremental backups if setup (still working on that) but paired with Talos it needed a whole redeployment. This is because Talos by default doesn't have some the necessary tools that Longhorn needs, specifically the `iscsi-tools` and the `util-linux-tools` as well as the `enforce:privileged` for the namespace.
[Longhorn Docs](https://longhorn.io/docs/1.10.1/advanced-resources/os-distro-specific/talos-linux-support/)
>Requirements
>
>You must meet the following requirements before installing Longhorn on a Talos Linux cluster.
>System Extensions
>
>Some Longhorn-dependent binary executables are not present in the default Talos root filesystem. To have access to these binaries, Talos offers system extension mechanism to extend the installation.
>
>    siderolabs/iscsi-tools: this extension enables iscsid daemon and iscsiadm to be available to all nodes for the Kubernetes persistent volumes operations.
>    siderolabs/util-linux-tools: this extension enables linux tool to be available to all nodes. For example, the fstrim binary is used for Longhorn volume trimming. 
>

Hence, why this typically needs a full redeploy, because you need a whole new image because you forgot the necessary extensions.

### Race Conditions
There's a few hiccups that can be had when deploying. You might be dilligent in trying to make sure your dependency chain at least makes sense, but then you might encounter something like the `MetalLB` namespace isn't created before the helm repo tries to place it there, even though you'd think a namespace should be basically instant. However that may not be that case and you might need to make a specific deployment step for it.

### Troubleshooting
Naturally we should know how to troubleshoot various things.
```bash
echo 'alias k=kubectl' >> ~/.bashrc && . ~/.bashrc
```

- Logs
```bash
flux logs --follow

```

- Check the deployment status of the current kustomizations
```bash
flux get kustomizations
```

- Get specific details about a kustomization (namespace should be flux-system)
```bash
k describe kustomization $kustomization -n $namespace
```

- Certificate, Order, CertificateRequest
```bash
k get certificate,order,challenge -n $namespace
k describe $target -n $namespace
```

- Sometimes deployments from helmreleases might hang also, and they might need to be deleted
```bash
k get hr -A
k delete $helmrelease -n $namespace
flux reconcile -n flux-system $kustomization --with-source
```



## Diving in
Now that you have an idea of what you have to be aware of, I can at least go through my whole setup and explain my rationale for some of my decisions.

### Talos Images
[Talos Factory](https://factory.talos.dev/)
- Cloud Server
- Talos Version
- NoCloud
- amd64 (probably)
- System Extensions
    - util-linux-tools
    - iscsi-tools
    - qemu-guest-agent

### Terraform - Proxmox 

I won't fully delve into this, my repo is [here](https://github.com/chin-tech/proxmox_talos_setup) but using an Infrastructure as Code platform is the ideal way to keep things repeatable.

### Creation

I won't run through all my yaml's since you could just clone a repo, but I'll at least highlight somethings I have that aren't just plain default to deploying a helmrelease.

- MetalLB
```yaml
  values:
    speaker:
      tolerations:
        # This toleration bypasses the standard control-plane taint
        - key: node-role.kubernetes.io/control-plane
          operator: Exists
          effect: NoSchedule
        # This toleration bypasses the standard master taint (older k8s versions)
        - key: node-role.kubernetes.io/master
          operator: Exists
          effect: NoSchedule
```

MetalLB has a "speaker" which gets deployed on nodes that need to advertise LoadBalancer IPs (Layer 2 via ARP/NDP or BGP). Control-Plane nodes are usually tainted to keep regular workloads off of them, so without this "toleration" the speaker won't schedule there. Production, that's ideal, cause they wouldn't typically carry service traffic, however in small home-lab environments this could lead to A LOT of confusion if a speaker isn't running on that node then you can get a service being "up" but unreachable. This just ensures everything will work regardless of what node it's on.

- Cert-Manager
```yaml
  values:
    installCRDs: true
    prometheus:
      enabled: false
    extraArgs:
      - --dns01-recursive-nameservers-only
      - --dns01-recursive-nameservers=1.1.1.1:53,1.0.0.1:53

```
If any helmrelease has custom resource definitions, tend to always install them, you will get issues otherwise. Currently, I'm not using prometheus so it saves some resources, and the extra args ensures the DNS resolution is more reliable since I'm using cloudflare as my DNS provider, so use cloudflare's server as the nameserver.


- Traefik
```yaml
  values:
    entrypoints:
      web:
        address: ":80"
        http:
          redirections:
            entryPoint:
              to: websecure
              scheme: https
              permanent: true
```
This is purely to redirect any web/http entry point to https/websecure since we're using LetsEncrypt/Cert-Manager, we want to make use of our SSL Domains.

- Longhorn
```yaml
  values:
    defaultSettings:
      defaultReplicaCount: 1
      allowRecurringJobWhileVolumeDetached: true

```

When longhorn deploys its default is 3 replicas per volume. This provides node-level redundancy. But when you only have 3 nodes in total, it can't schedule or put 3 replicas on distinct nodes for failover purposes, so it will always be degraded. This fixes the replica count to 1, which is perfectly fine for a small home-lab. The `allowRecurringJobWhileVolumeDetached` is kind of self-explanatory, if a volume gets scaled down and isn't attached, it still would have snapshots or backups run.


## Closing

This was a wonderful start to kubernetes and honestly took me much longer than it should have. Because there was a lot of new technology involved and trying to orchestrate it all is a pain. The ideas behind it all are all concrete in my head but the practice of it is much harder than the idea. Especially when you have to write yaml without schemas. So make sure you have a yamlls and point it at jsonschema to save yourself some migraines trying to figure out what possible options something has and make use of an LLM when you struggle because it's getting surprisingly good at troubleshooting especially some of the basic pitfalls we'll have along the way. Just be sure to pay attention, one cloudflare outage and your whole ability to debug will be gone :)







