/*
 * Copyright © 2017-2025 WireGuard LLC. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */
package com.wireguard.android.util

import android.util.Log
import com.wireguard.config.Config
import com.wireguard.config.InetNetwork
import com.wireguard.config.Peer
import java.math.BigInteger
import java.net.InetAddress
import java.net.UnknownHostException

object AllowedIpsSubtractor {
    private const val TAG = "WGSTunnel/AllowedIPs"

    /**
     * If Interface.wstunnel is non-empty, resolve Interface.wstunnelHost and remove its IP(s)
     * from every peer AllowedIPs, returning a NEW Config (in-memory only).
     */
    @Throws(UnknownHostException::class)
    fun applyIfNeeded(original: Config): Config {
        val iface = original.`interface`
        val wstunnelCmd = iface.wstunnel?.trim().orEmpty()
        if (wstunnelCmd.isEmpty()) return original

        val host = iface.wstunnelHost?.trim().orEmpty()
        Log.i(TAG, "Applying AllowedIPs subtraction for wstunnel. host=$host")
        if (host.isEmpty()) {
            // If wstunnel is set but host isn't, we can’t do the subtraction reliably.
            // Fail fast so user fixes config.
            throw UnknownHostException("wstunnel_host is empty (required when wstunnel is set)")
        }

        val resolvedIps = resolveHost(host)
        if (resolvedIps.isEmpty()) {
            throw UnknownHostException("wstunnel_host resolved to empty: $host")
        }
        Log.i(TAG, "Resolved wstunnel_host=$host to ${resolvedIps.joinToString(",") { it.hostAddress }}")

        val newPeers = original.peers.map { peer ->
            val adjusted = subtractMany(peer.allowedIps, resolvedIps)
            Log.i(TAG, "Peer ${peer.publicKey.toBase64()} effective AllowedIPs=${adjusted.joinToString(",")}")
            if (adjusted == peer.allowedIps) peer
            else rebuildPeerWithAllowedIps(peer, adjusted)
        }

        val builder = Config.Builder()
        builder.setInterface(iface)
        newPeers.forEach { builder.addPeer(it) }
        return builder.build()
    }

    private fun resolveHost(host: String): List<InetAddress> {
        return try {
            InetAddress.getAllByName(host).toList()
        } catch (e: UnknownHostException) {
            Log.e(TAG, "DNS failed for wstunnel_host=$host", e)
            throw e
        }
    }

    private fun rebuildPeerWithAllowedIps(peer: Peer, newAllowed: Set<InetNetwork>): Peer {
        val b = Peer.Builder()
            .setPublicKey(peer.publicKey)

        peer.preSharedKey.ifPresent { b.setPreSharedKey(it) }
        peer.endpoint.ifPresent { b.setEndpoint(it) }
        peer.persistentKeepalive.ifPresent { b.setPersistentKeepalive(it) }

        b.addAllowedIps(newAllowed)
        return b.build()
    }

    private fun subtractMany(
        allowed: Set<InetNetwork>,
        excludedIps: List<InetAddress>
    ): Set<InetNetwork> {
        var current = allowed
        for (ip in excludedIps) {
            current = subtractOneIp(current, ip)
        }
        return current
    }

    private fun subtractOneIp(
        allowed: Set<InetNetwork>,
        excludedIp: InetAddress
    ): Set<InetNetwork> {
        val out = LinkedHashSet<InetNetwork>()
        for (net in allowed) {
            val pieces = subtractIpFromNetwork(net, excludedIp)
            out.addAll(pieces)
        }
        return out
    }

    /**
     * If excludedIp is not inside net -> return [net]
     * If it is inside -> return 0..N InetNetwork CIDRs that cover net minus that single IP.
     *
     * This matches the “subtract a host from a CIDR then re-express as minimal CIDRs” behavior.
     */
    private fun subtractIpFromNetwork(net: InetNetwork, excludedIp: InetAddress): List<InetNetwork> {
        val netAddr = net.address
        if (netAddr.javaClass != excludedIp.javaClass) return listOf(net)

        val bits = netAddr.address.size * 8
        val mask = net.mask

        val start = networkStart(netAddr, mask, bits)
        val end = networkEnd(start, mask, bits)
        val ip = inetToBigInt(excludedIp)

        if (ip < start || ip > end) return listOf(net)

        if (start == end) return emptyList()

        val ranges = ArrayList<Pair<BigInteger, BigInteger>>(2)
        if (ip == start) ranges.add((start + BigInteger.ONE) to end)
        else if (ip == end) ranges.add(start to (end - BigInteger.ONE))
        else {
            ranges.add(start to (ip - BigInteger.ONE))
            ranges.add((ip + BigInteger.ONE) to end)
        }

        val result = ArrayList<InetNetwork>()
        for ((rs, re) in ranges) {
            result.addAll(rangeToCidrs(rs, re, bits))
        }
        return result
    }

    private fun inetToBigInt(addr: InetAddress): BigInteger = BigInteger(1, addr.address)

    private fun networkStart(addr: InetAddress, mask: Int, bits: Int): BigInteger {
        val ip = inetToBigInt(addr)
        val m = prefixMask(bits, mask)
        return ip.and(m)
    }

    private fun networkEnd(start: BigInteger, mask: Int, bits: Int): BigInteger {
        val hostBits = bits - mask
        val sizeMinus1 = BigInteger.ONE.shiftLeft(hostBits).subtract(BigInteger.ONE)
        return start.add(sizeMinus1)
    }

    private fun prefixMask(bits: Int, mask: Int): BigInteger {
        if (mask == 0) return BigInteger.ZERO
        val allOnes = BigInteger.ONE.shiftLeft(bits).subtract(BigInteger.ONE)
        val shifted = allOnes.shiftLeft(bits - mask)
        return shifted.and(allOnes)
    }

    /**
     * Convert an inclusive range start..end into minimal CIDRs.
     */
    private fun rangeToCidrs(start: BigInteger, end: BigInteger, bits: Int): List<InetNetwork> {
        val out = ArrayList<InetNetwork>()
        var cur = start
        while (cur <= end) {
            val tz = cur.lowestSetBit.coerceAtLeast(0)
            val maxAlignedSizePow = tz.coerceAtMost(bits)
            val remaining = end.subtract(cur).add(BigInteger.ONE)
            val maxRemainingPow = remaining.bitLength() - 1

            val sizePow = minOf(maxAlignedSizePow, maxRemainingPow)
            val prefixLen = bits - sizePow

            val cidrStr = "${bigIntToInet(cur, bits).hostAddress}/$prefixLen"
            out.add(InetNetwork.parse(cidrStr))

            cur = cur.add(BigInteger.ONE.shiftLeft(sizePow))
        }
        return out
    }

    private fun bigIntToInet(value: BigInteger, bits: Int): InetAddress {
        val byteLen = bits / 8
        var raw = value.toByteArray()
        if (raw.size > 1 && raw[0] == 0.toByte()) raw = raw.copyOfRange(1, raw.size)
        val out = ByteArray(byteLen)
        val start = byteLen - raw.size
        for (i in raw.indices) out[start + i] = raw[i]
        return InetAddress.getByAddress(out)
    }
}
