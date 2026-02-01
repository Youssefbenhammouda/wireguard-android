/*
 * Copyright © 2017-2025 WireGuard LLC. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */
package com.wireguard.android.wstunnel

import android.content.Context
import android.util.Log
import java.io.File
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.TimeUnit

object WstunnelRunner {
    private const val TAG = "WGSTunnel/Wstunnel"
    private val running = ConcurrentHashMap<String, Process>()

    fun startIfNeeded(ctx: Context, tunnelName: String, wstunnelCmd: String) {
        val cmd = wstunnelCmd.trim()
        if (cmd.isEmpty()) return

        // If already running for this tunnel, stop it first (prevents duplicates).
        stop(tunnelName)

        val argv = splitCommandLine(cmd)
        if (argv.isEmpty()) return

        // Replace executable with embedded path.
        val exe = embeddedPath(ctx)
        argv[0] = exe

        // Sanity: file exists
        val f = File(exe)
        if (!f.exists()) throw IllegalStateException("Embedded wstunnel missing at $exe")

        Log.i(TAG, "Starting wstunnel for $tunnelName: ${argv.joinToString(" ")}")

        val pb = ProcessBuilder(argv)
        pb.redirectErrorStream(true)

        val proc = pb.start()
        running[tunnelName] = proc

        // Optional: pipe logs (helpful for debugging)
        Thread {
            try {
                proc.inputStream.bufferedReader().useLines { lines ->
                    lines.forEach { Log.i(TAG, "[$tunnelName] $it") }
                }
            } catch (_: Throwable) {
            }
        }.apply { isDaemon = true }.start()
    }

    fun stop(tunnelName: String) {
        val proc = running.remove(tunnelName) ?: return
        Log.i(TAG, "Stopping wstunnel for $tunnelName")
        proc.destroy()
        // Give it a moment, then force-kill if needed.
        try {
            proc.waitFor(500, TimeUnit.MILLISECONDS)
        } catch (_: Throwable) {
        }
        if (proc.isAlive) proc.destroyForcibly()
    }

    fun stopAll() {
        running.keys.toList().forEach { stop(it) }
    }

    private fun embeddedPath(ctx: Context): String {
        // nativeLibraryDir is where Android extracts lib/<abi>/ files.
        // Android 10+ forbids exec from writable app home dir, but nativeLibraryDir is fine.
        val dir = ctx.applicationInfo.nativeLibraryDir
        return "$dir/${WstunnelEmbedded.LIB_NAME}"
    }

    /**
     * Minimal shell-like splitter:
     * - supports quotes: "..." and '...'
     * - supports backslash escaping inside double quotes and unquoted text
     */
    private fun splitCommandLine(cmd: String): MutableList<String> {
        val out = mutableListOf<String>()
        val sb = StringBuilder()
        var i = 0
        var inSingle = false
        var inDouble = false

        fun flush() {
            if (sb.isNotEmpty()) {
                out.add(sb.toString())
                sb.setLength(0)
            }
        }

        while (i < cmd.length) {
            val c = cmd[i]
            when {
                inSingle -> {
                    if (c == '\'') inSingle = false else sb.append(c)
                }
                inDouble -> {
                    when (c) {
                        '"' -> inDouble = false
                        '\\' -> {
                            if (i + 1 < cmd.length) {
                                i++
                                sb.append(cmd[i])
                            }
                        }
                        else -> sb.append(c)
                    }
                }
                else -> {
                    when (c) {
                        ' ', '\t', '\n', '\r' -> flush()
                        '\'' -> inSingle = true
                        '"' -> inDouble = true
                        '\\' -> {
                            if (i + 1 < cmd.length) {
                                i++
                                sb.append(cmd[i])
                            }
                        }
                        else -> sb.append(c)
                    }
                }
            }
            i++
        }
        flush()
        return out
    }
}
