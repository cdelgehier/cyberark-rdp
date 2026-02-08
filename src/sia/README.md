# SIA Connect (RDP Gateway) Module

Ce module implémente le protocole MS-TSGU (Terminal Services Gateway) pour les connexions RDP via une passerelle HTTP(S). Utilisé par CyberArk SIA Connect.

## Structure

```
sia/
├── README.md           # Cette documentation
├── RDG_PROTOCOL.md     # Spécification technique complète du protocole
├── mod.rs              # Module racine
├── gateway.rs          # Implémentation de la connexion Gateway
└── rdg_packets.rs      # Structures de packets RDG binaires
```

## Fonctionnement

### 1. Établissement de la Connexion

Le protocole RDP Gateway utilise **deux canaux HTTP** pour tunneliser le trafic RDP:

- **OUT Channel** (Server → Client): Utilise HTTP chunked encoding
- **IN Channel** (Client → Server): Pour envoyer les commandes

```rust
let gateway = GatewayConnection::new(
    gateway_hostname,
    target_server,
    target_port,
    sso_token,
    password,
)?;

let stream = gateway.connect()?;
```

### 2. Authentification

L'authentification utilise **PAA (Pluggable Authentication Architecture)** avec un token SSO:

```
Authorization: RDGAuth paa_token_here
```

Le token est extrait du fichier RDP (champ `alternate shell` ou `gatewayaccesstoken`).

### 3. Handshake RDG

Après l'établissement des canaux, un handshake RDG binaire est effectué:

1. **HANDSHAKE_REQUEST** (0x0001)
2. **TUNNEL_CREATE** (0x0003)
3. **TUNNEL_AUTH** (0x0005)
4. **CHANNEL_CREATE** (0x0007)

Voir [RDG_PROTOCOL.md](RDG_PROTOCOL.md) pour les détails complets.

## Seed Payload

⚠️ **Important**: Après HTTP 200 OK, le serveur envoie 10 bytes aléatoires qui doivent être **ignorés** avant de commencer à lire les chunks.

```rust
// Le seed payload est automatiquement sauté dans GatewayStream::new()
let stream = GatewayStream::new(in_channel, out_channel, seed_payload);
```

## HTTP Chunked Encoding

Le canal OUT utilise le transfer-encoding chunked. Notre implémentation utilise une machine à états pour le décodage non-bloquant:

```rust
enum ChunkStateEnum {
    LengthHeader,  // Lecture de la taille hex
    Data,          // Lecture des données
    Footer,        // Consommation de \r\n
    End,           // Fin du stream
}
```

## État Actuel

### ✅ Implémenté
- Établissement des canaux HTTP (IN/OUT)
- Authentification PAA
- Gestion du seed payload
- HTTP chunked encoding (lecture)
- Structures de packets RDG binaires

### ⚠️ En Cours / Problèmes Connus

Le handshake RDG complet n'aboutit pas actuellement avec les serveurs CyberArk SIA Connect. Le serveur ferme la connexion après réception du handshake request.

**Note**: Même FreeRDP échoue avec les mêmes serveurs en mode SIA Connect, suggérant une configuration serveur spécifique.

## Utilisation

Ce module est utilisé automatiquement quand un fichier RDP contient les paramètres Gateway:

```ini
gatewayusagemethod:i:1
gatewayhostname:s:gateway.example.com
alternate shell:s:/sso <token> /sso_type rdp_file
```

Le code dans `connection.rs` détecte automatiquement le mode Gateway et utilise ce module.

## Mode Legacy PSM

Pour les connexions PSM sans Gateway, voir `connection.rs` qui gère les connexions RDP directes avec:
- Format username non-standard: `domain\user@uuid`
- CredSSP désactivé: `EnableCredSspSupport:i:0`
- Authentification TLS standard

## Références

- [MS-TSGU Specification](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-tsgu/)
- [FreeRDP Implementation](https://github.com/FreeRDP/FreeRDP/blob/master/libfreerdp/core/gateway/rdg.c)
- [RFC 7230 - HTTP Chunked Transfer](https://tools.ietf.org/html/rfc7230#section-4.1)

---

*Pour la documentation technique détaillée, voir [RDG_PROTOCOL.md](RDG_PROTOCOL.md)*
