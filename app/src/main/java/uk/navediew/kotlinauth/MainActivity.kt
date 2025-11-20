package uk.navediew.kotlinauth

import android.app.Activity
import android.content.Intent
import android.os.Bundle
import androidx.appcompat.app.AppCompatActivity
import androidx.biometric.BiometricManager
import androidx.biometric.BiometricPrompt
import androidx.credentials.CreatePublicKeyCredentialRequest
import androidx.credentials.CreatePublicKeyCredentialResponse
import androidx.credentials.GetCredentialResponse
import androidx.credentials.GetPublicKeyCredentialOption
import androidx.credentials.PublicKeyCredential
import androidx.credentials.provider.PendingIntentHandler
import androidx.credentials.webauthn.AuthenticatorAssertionResponse
import androidx.credentials.webauthn.AuthenticatorAttestationResponse
import androidx.credentials.webauthn.FidoPublicKeyCredential
import androidx.credentials.webauthn.PublicKeyCredentialCreationOptions
import androidx.credentials.webauthn.PublicKeyCredentialRequestOptions
import kotlinx.serialization.Serializable
import kotlinx.serialization.encodeToString
import kotlinx.serialization.json.Json
import java.math.BigInteger
import java.security.KeyPair
import java.security.KeyPairGenerator
import java.security.MessageDigest
import java.security.SecureRandom
import java.security.Signature
import java.security.interfaces.ECPrivateKey
import java.security.interfaces.ECPublicKey
import java.security.spec.ECGenParameterSpec
import java.security.spec.ECPoint

class MainActivity : AppCompatActivity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        if (intent.action == "uk.navediew.kotlinauth.CREATE_PASSKEY") {
            val request = PendingIntentHandler.retrieveProviderCreateCredentialRequest(intent)
            val accountId = intent.getStringExtra("uk.navediew.kotlinauth.EXTRA_KEY_ACCOUNT_ID")
            if (request != null && request.callingRequest is CreatePublicKeyCredentialRequest) {
                val publicKeyRequest: CreatePublicKeyCredentialRequest = request.callingRequest as CreatePublicKeyCredentialRequest
                createPasskey(
                    publicKeyRequest.requestJson,
                    request.callingAppInfo,
                    publicKeyRequest.clientDataHash,
                    accountId
                )
            }
        } else if (intent.action == "uk.navediew.kotlinauth.GET_PASSKEY"){
            val getRequest = PendingIntentHandler.retrieveProviderGetCredentialRequest(intent)
            val publicKeyRequests = getRequest!!.credentialOptions as List<GetPublicKeyCredentialOption>
            val requestInfo = intent.getBundleExtra("CREDENTIAL_DATA")
            val credIdEnc = requestInfo?.getString("credId")
            val requestJson = Json.decodeFromString<GetPublicKeyCredentialRequestJson>(publicKeyRequests[0].requestJson)
            val credId = CredmanUtils.b64Decode(credIdEnc)
            val rpid = CredmanUtils.validateRpId(getRequest.callingAppInfo,requestJson.rpId)
            val passkey = MyCredentialDataManager.load(this,rpid,credId!!)
            val privateKey = passkey!!.keyPair!!.private as ECPrivateKey
            val uid = passkey.userHandle
            val origin = CredmanUtils.appInfoToOrigin(getRequest.callingAppInfo)
            val packageName = getRequest.callingAppInfo.packageName
            val clientDataHash = publicKeyRequests[0].requestData.getByteArray("androidx.credentials.BUNDLE_KEY_CLIENT_DATA_HASH")
            validatePasskey(
                publicKeyRequests[0].requestJson,
                origin,
                packageName,
                uid,
                passkey.displayName,
                credId,
                privateKey,
                clientDataHash
            )
        }

    }

    private fun createPasskey(
        requestJson: String,
        callingAppInfo: androidx.credentials.provider.CallingAppInfo?,
        clientDataHash: ByteArray?,
        _accountId: String?
    ) {
        val request = PublicKeyCredentialCreationOptions(requestJson)
        val biometricPrompt = BiometricPrompt(
            this,
            this.mainExecutor,
        object : BiometricPrompt.AuthenticationCallback() {
            override fun onAuthenticationError(
                errorCode: Int, errString: CharSequence
            ) {
                super.onAuthenticationError(errorCode, errString)
                finish()
            }

            override fun onAuthenticationFailed() {
                super.onAuthenticationFailed()
                finish()
            }

            override fun onAuthenticationSucceeded(
                result: BiometricPrompt.AuthenticationResult
            ) {
                super.onAuthenticationSucceeded(result)

                // Generate a credentialId
                val credentialId = ByteArray(32)
                SecureRandom().nextBytes(credentialId)

                // Generate a credential key pair
                val spec = ECGenParameterSpec("secp256r1")
                val keyPairGen = KeyPairGenerator.getInstance("EC")
                keyPairGen.initialize(spec)
                val keyPair = keyPairGen.genKeyPair()


                // check if rpid is a subdomain of origin
                val rpid = CredmanUtils.validateRpId(callingAppInfo!!,request.rp.id)

                // Save passkey in your database as per your own implementation

                MyCredentialDataManager.save(this@MainActivity, MyCredentialDataManager.Credential(
                    rpid = rpid,
                    serviceName = request.rp.name,
                    credentialId = credentialId,
                    displayName = request.user.displayName,
                    userHandle = request.user.id,
                    keyPair = keyPair
                ))

                // Create AuthenticatorAttestationResponse object to pass to
                // FidoPublicKeyCredential

                val response = AuthenticatorAttestationResponse(
                    requestOptions = request,
                    credentialId = credentialId,
                    credentialPublicKey = getPublicKeyFromKeyPair(keyPair), //CBOR
                    origin = CredmanUtils.appInfoToOrigin(callingAppInfo),
                    up = true,
                    uv = true,
                    be = true,
                    bs = true,
                    packageName = callingAppInfo.packageName,
                    clientDataHash = clientDataHash
                )

                val credential = FidoPublicKeyCredential(
                    rawId = credentialId, response = response , authenticatorAttachment = "platform"
                )

                val credentialJson = populateEasyAccessorFields(credential.json(),rpid, keyPair,credentialId)

                val result = Intent()

                val createPublicKeyCredResponse =
                    CreatePublicKeyCredentialResponse(credentialJson)

                // Set the CreateCredentialResponse as the result of the Activity
                PendingIntentHandler.setCreateCredentialResponse(
                    result, createPublicKeyCredResponse
                )
                setResult(Activity.RESULT_OK, result)
                finish()
            }
        }
        )
        val promptInfo = BiometricPrompt.PromptInfo.Builder()
            .setTitle("Use your screen lock")
            .setSubtitle("Create passkey for ${request.rp.name}")
            .setAllowedAuthenticators(
                BiometricManager.Authenticators.BIOMETRIC_STRONG
                /* or BiometricManager.Authenticators.DEVICE_CREDENTIAL */
            )
            .setNegativeButtonText("Cancel")
            .build()
        biometricPrompt.authenticate(promptInfo)
    }

    private fun populateEasyAccessorFields(json: String, rpid:String , keyPair: KeyPair, credentialId: ByteArray):String{
        val response = Json.decodeFromString<CreatePublicKeyCredentialResponseJson>(json)
        response.response.publicKeyAlgorithm = -7 // ES256
        response.response.publicKey = CredmanUtils.b64Encode(keyPair.public.encoded)
        response.response.authenticatorData = getAuthData(rpid, credentialId, keyPair)
        return Json.encodeToString(response)

    }
    private fun getAuthData(rpid:String, credentialRawId:ByteArray, keyPair: KeyPair ):String{
        val AAGUID = "00000000000000000000000000000000"
        check(AAGUID.length % 2 == 0) { "AAGUID Must have an even length" }
        val rpIdHash:ByteArray = MessageDigest.getInstance("SHA-256").digest(rpid.toByteArray())
        val flags: ByteArray = byteArrayOf(0x5d.toByte())
        val signCount:ByteArray = byteArrayOf(0x00, 0x00, 0x00, 0x00)
        val aaguid = AAGUID.chunked(2)
            .map { it.toInt(16).toByte() }
            .toByteArray()
        val credentialIdLength:ByteArray = byteArrayOf(0x00, credentialRawId.size.toByte()) // = 20 bytes
        val credentialPublicKey:ByteArray =getPublicKeyFromKeyPair(keyPair)
        val retVal = rpIdHash + flags + signCount + aaguid + credentialIdLength + credentialRawId + credentialPublicKey
        return CredmanUtils.b64Encode(retVal)
    }

    fun validatePasskey(requestJson:String, origin:String, packageName:String, uid:ByteArray, username:String, credId:ByteArray, privateKey: ECPrivateKey, clientDataHash: ByteArray?){
        val request = PublicKeyCredentialRequestOptions(requestJson)
        val biometricPrompt = BiometricPrompt(
            this,
            this.mainExecutor,
            object : BiometricPrompt.AuthenticationCallback() {
                override fun onAuthenticationError(
                    errorCode: Int, errString: CharSequence
                ) {
                    super.onAuthenticationError(errorCode, errString)
                    finish()
                }

                override fun onAuthenticationFailed() {
                    super.onAuthenticationFailed()
                    finish()
                }

                override fun onAuthenticationSucceeded(
                    result: BiometricPrompt.AuthenticationResult
                ) {
                    super.onAuthenticationSucceeded(result)
                    val response = AuthenticatorAssertionResponse(
                        requestOptions = request,
                        credentialId = credId,
                        origin = origin,
                        up = true,
                        uv = true,
                        be = true,
                        bs = true,
                        userHandle = uid,
                        clientDataHash = clientDataHash
                    )


                    val sig = Signature.getInstance("SHA256withECDSA")
                    sig.initSign(privateKey)
                    sig.update(response.dataToSign())
                    response.signature = sig.sign()

                    val credential = FidoPublicKeyCredential(
                        rawId = credId, response = response
                        , authenticatorAttachment = "platform")


                    // add clientDataJSON to the response
                    val clientDataJSONb64 = getClientDataJSONb64(origin, CredmanUtils.b64Encode( request.challenge))
                    val delimiter = "response\":{"
                    val credentialJson = credential.json().substringBeforeLast(delimiter)+ delimiter +
                            "\"clientDataJSON\":\"$clientDataJSONb64\","+
                            credential.json().substringAfterLast(delimiter)


                    val result = Intent()
                    val passkeyCredential = PublicKeyCredential(credentialJson)
                    PendingIntentHandler.setGetCredentialResponse(
                        result, GetCredentialResponse(passkeyCredential)
                    )
                    setResult(RESULT_OK, result)
                    finish()
                }
            }
        )

        val promptInfo = BiometricPrompt.PromptInfo.Builder()
            .setTitle("Use your screen lock")
            .setSubtitle("Use passkey for ${request.rpId}")
            .setAllowedAuthenticators(
                BiometricManager.Authenticators.BIOMETRIC_STRONG
                /* or BiometricManager.Authenticators.DEVICE_CREDENTIAL */
            )
            .setNegativeButtonText("Cancel") // this needs to be added when using BIOMETRIC
            .build()
        biometricPrompt.authenticate(promptInfo)
    }


    private fun getClientDataJSONb64(origin: String,challenge:String): String {
        val origin = origin.replace(Regex("/$"), "")
        val jsonString = "{\"type\":\"webauthn.get\",\"challenge\":\"$challenge\",\"origin\":\"$origin\",\"crossOrigin\":false}"
        val jsonByteArray = jsonString.toByteArray()
        return CredmanUtils.b64Encode(jsonByteArray)
    }


    @Serializable
    private data class CreatePublicKeyCredentialResponseJson(
        //RegistrationResponseJSON
        val id:String,
        val rawId: String,
        val response: Response,
        val authenticatorAttachment: String?,
        val clientExtensionResults: EmptyClass = EmptyClass(),
        val type: String,
    ) {
        @Serializable
        data class Response(
            //AuthenticatorAttestationResponseJSON
            val clientDataJSON: String? = null,
            var authenticatorData: String? = null,
            val transports: List<String>? = arrayOf("internal").toList(),
            var publicKey: String? = null, // easy accessors fields
            var publicKeyAlgorithm: Long? =null, // easy accessors fields
            val attestationObject: String? // easy accessors fields
        )
        @Serializable
        class EmptyClass
    }

    private fun getPublicKeyFromKeyPair(keyPair: KeyPair?): ByteArray {
        // credentialPublicKey CBOR
        if (keyPair==null) return ByteArray(0)
        if (keyPair.public !is ECPublicKey) return ByteArray(0)

        val ecPubKey = keyPair.public as ECPublicKey
        val ecPoint: ECPoint = ecPubKey.w

        // for now, only covers ES256
        if (ecPoint.affineX.bitLength() > 256 || ecPoint.affineY.bitLength() > 256) return ByteArray(0)

        val byteX = bigIntToByteArray32(ecPoint.affineX)
        val byteY = bigIntToByteArray32(ecPoint.affineY)

        // refer to RFC9052 Section 7 for details
        return "A5010203262001215820".chunked(2).map { it.toInt(16).toByte() }.toByteArray() +
                byteX+
                "225820".chunked(2).map { it.toInt(16).toByte() }.toByteArray() +
                byteY
    }

    private fun bigIntToByteArray32(bigInteger: BigInteger):ByteArray{
        var ba = bigInteger.toByteArray()
        if(ba.size < 32) {
            // append zeros in front
            ba = ByteArray(32) + ba
        }
        // get the last 32 bytes as bigint conversion sometimes put extra zeros at front
        return ba.copyOfRange(ba.size - 32, ba.size)
    }


}

