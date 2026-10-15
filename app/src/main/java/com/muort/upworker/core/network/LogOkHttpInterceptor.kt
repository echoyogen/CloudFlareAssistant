package com.muort.upworker.core.network

import com.muort.upworker.core.log.LogRepository
import okhttp3.Interceptor
import okhttp3.Response
import javax.inject.Inject

class LogOkHttpInterceptor @Inject constructor() : Interceptor {
    companion object {
        private val SENSITIVE_HEADERS = setOf(
            "authorization",
            "x-auth-email",
            "x-auth-key",
            "x-auth-token",
            "cf-access-client-id",
            "cf-access-client-secret",
            "cookie",
            "set-cookie"
        )

        private fun redactHeaderValue(name: String, value: String): String =
            if (name.lowercase() in SENSITIVE_HEADERS) "██" else value
    }

    override fun intercept(chain: Interceptor.Chain): Response {
        // 开关关闭时直接放行，避免不必要的 body 读取与字符串拼接开销
        if (!LogRepository.isEnabled) {
            return chain.proceed(chain.request())
        }

        val request = chain.request()
        val time = java.time.ZonedDateTime.now(java.time.ZoneId.of("Asia/Shanghai"))
        val timeStr = time.format(java.time.format.DateTimeFormatter.ofPattern("yyyy HH:mm:ss z"))
        val requestLog = buildString {
            append("\n--- 请求 ---    $timeStr\n")
            append("URL: ${request.url}\n")
            append("Method: ${request.method}\n")
            request.headers.forEach { append("Header: ${it.first}: ${redactHeaderValue(it.first, it.second)}\n") }
            if (request.body != null) {
                // 请求正文可能包含 API Token、R2 密钥等，日志中永不记录正文。
                append("Body: [redacted]\n")
            }
        }
        LogRepository.appendLog(requestLog)
        val response = try {
            chain.proceed(request)
        } catch (e: Exception) {
            LogRepository.appendLog("--- 响应异常 ---\n${e}\n")
            throw e
        }
        val time2 = java.time.ZonedDateTime.now(java.time.ZoneId.of("Asia/Shanghai"))
        val timeStr2 = time2.format(java.time.format.DateTimeFormatter.ofPattern("yyyy HH:mm:ss z"))
        val responseLog = buildString {
            append("--- 响应 ---    $timeStr2\n")
            append("URL: ${response.request.url}\n")
            append("Code: ${response.code}\n")
            response.headers.forEach { append("Header: ${it.first}: ${redactHeaderValue(it.first, it.second)}\n") }
            // 响应正文可能包含新建密钥等敏感信息，日志中永不记录正文。
            append("Body: [redacted]\n")
        }
        LogRepository.appendLog(responseLog)
        return response
    }
}
