package uk.navediew.kotlinauth

import java.security.MessageDigest
import kotlin.io.encoding.Base64
import kotlin.io.encoding.ExperimentalEncodingApi

object CredmanUtils {
    fun appInfoToOrigin(info: androidx.credentials.provider.CallingAppInfo): String {
        val cert = info.signingInfo.apkContentsSigners[0].toByteArray()
        val certHash = MessageDigest.getInstance("SHA-256").digest(cert)
        return "android:apk-key-hash:${b64Encode(certHash)}"
    }

    @OptIn(ExperimentalEncodingApi::class)
    fun b64Encode(data:ByteArray):String{
        // replace with import androidx.credentials.webauthn.WebAuthnUtils in future
        return Base64.UrlSafe.encode(data).replace("=","")
    }

    @OptIn(ExperimentalEncodingApi::class)
    fun b64Decode(data:String?):ByteArray?{
        // replace with import androidx.credentials.webauthn.WebAuthnUtils in future
        if(data ==null || data.isEmpty()) return null
        return Base64.UrlSafe.decode(data)
    }

    fun validateRpId(info: androidx.credentials.provider.CallingAppInfo, rpid:String): String{
        var origin = appInfoToOrigin(info)
        val rpIdForRexEx = rpid.replace(".","""\.""")
        if (Regex("""^https://([A-Za-z0-9\-.]*\.)?"""+rpIdForRexEx+"""($|/.*)""").matches(origin)){
            //take out  "https://" and trailing slash "/" to make origin a pure domain.
            origin = rpid
        }
        return origin
    }
}
