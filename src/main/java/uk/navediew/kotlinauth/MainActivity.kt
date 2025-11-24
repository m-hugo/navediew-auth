package uk.navediew.authlin

import java.math.BigInteger
import java.io.ByteArrayInputStream
import java.io.ByteArrayOutputStream
import java.io.ObjectInput
import java.io.ObjectInputStream
import java.io.ObjectOutputStream
import java.security.KeyPair
import java.security.KeyPairGenerator
import java.security.MessageDigest
import java.security.SecureRandom
import java.security.Signature
import java.security.interfaces.ECPrivateKey
import java.security.interfaces.ECPublicKey
import java.security.spec.ECGenParameterSpec
import java.security.spec.ECPoint

import android.app.Activity
import android.content.Intent
import android.os.Bundle
import android.os.CancellationSignal
import android.hardware.biometrics.BiometricManager
import android.hardware.biometrics.BiometricPrompt
import android.content.DialogInterface
import android.annotation.SuppressLint
import android.widget.TextView;
import android.util.TypedValue;
import android.view.Gravity;
import android.util.Base64;
import android.content.Context
import android.content.SharedPreferences

import androidx.credentials.exceptions.CreateCredentialException
import androidx.credentials.exceptions.CreateCredentialCancellationException
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
import androidx.credentials.provider.CallingAppInfo

import kotlinx.serialization.Serializable
import kotlinx.serialization.encodeToString
import kotlinx.serialization.json.Json

object MyCredentialDataManager {
	fun save(context: Context, credential: Credential){
		val credSet= loadCredSet(context)
		val cred = CredSet.SerializedCred(
			credential.rpid,
			credential.serviceName,
			credential.credentialId,
			credential.userHandle,
			credential.displayName,
			WebAuthnUtils.b64Encode(credential.keyPair!!.toByteArray())
		)
		credSet.list.add(cred)
		saveCredSet(context, credSet)
	}

	fun load(context: Context, rpid:String): MutableList<Credential> {
		val credSet = loadCredSet(context)
		val list:MutableList<Credential> = mutableListOf()
		credSet.list.forEach{if(it.rpid==rpid) list.add(convertCred(it))}
		return list
	}
	fun loadAll(context: Context): MutableList<Credential> {
		val credSet = loadCredSet(context)
		val list:MutableList<Credential> = mutableListOf()
		credSet.list.forEach{list.add(convertCred(it))}
		return list
	}
	fun load(context: Context, rpid: String, credentialId: ByteArray):Credential?{
		val credSet= loadCredSet(context)
		credSet.list.forEach{if(it.rpid==rpid && it.credentialId.contentEquals(credentialId)) return convertCred(it)}
		return null
	}

	fun delete(context: Context, rpid: String, credentialId: ByteArray){
		val newCredSet = CredSet()
		loadCredSet(context).list.forEach{
			if(!(it.rpid==rpid && it.credentialId.contentEquals(credentialId))) newCredSet.list.add(it)
		}
		saveCredSet(context, newCredSet)
	}

	fun loadSetJsonStr(context: Context):String{
		return context.getSharedPreferences(context.packageName, Activity.MODE_PRIVATE).getString("PREF_CREDENTIAL_SET", "")?:""
	}
	fun replaceJson(context: Context, str: String){
		val sharedPref = context.getSharedPreferences(context.packageName, Activity.MODE_PRIVATE)
		val prefsEditor: SharedPreferences.Editor = sharedPref.edit()
		prefsEditor.putString("PREF_CREDENTIAL_SET", str)
		prefsEditor.apply()
	}

	private fun loadCredSet(context: Context):CredSet{
		val setjson = loadSetJsonStr(context)
		return if(setjson.isEmpty()) CredSet() else Json.decodeFromString<CredSet>(setjson)
	}

	private fun convertCred(cred:CredSet.SerializedCred):Credential{
		return Credential(
			cred.rpid,
			cred.serviceName,
			cred.credentialId,
			cred.userHandle,
			cred.displayName,
			fromByteArray(WebAuthnUtils.b64Decode(cred.keyPair))
		)
	}

	private fun saveCredSet(context: Context, credSet: CredSet){
		replaceJson(context, Json.encodeToString(credSet))
	}

	data class Credential(
		val rpid:String,
		val serviceName:String = rpid,
		val credentialId:ByteArray,
		val userHandle:ByteArray = byteArrayOf(),
		val displayName:String = "",
		val keyPair:KeyPair? = null
	)

	@Serializable
	data class CredSet(
		var list:MutableList<SerializedCred> = mutableListOf()
	){
		@Serializable
		data class SerializedCred(
			val rpid:String,
			val serviceName:String = rpid,
			val credentialId:ByteArray,
			val userHandle:ByteArray = byteArrayOf(),
			val displayName:String = "",
			val keyPair: String? = null,
		)
	}

	private fun fromByteArray(byteArray: ByteArray?): KeyPair? {
		if (byteArray == null) return null
		val byteArrayInputStream = ByteArrayInputStream(byteArray)
		val objectInput: ObjectInput
		objectInput = ObjectInputStream(byteArrayInputStream)
		val result = objectInput.readObject() as KeyPair?
		objectInput.close()
		byteArrayInputStream.close()
		return result
	}

	private fun KeyPair.toByteArray(): ByteArray {
		val byteArrayOutputStream = ByteArrayOutputStream()
		val objectOutputStream = ObjectOutputStream(byteArrayOutputStream)
		objectOutputStream.writeObject(this)
		objectOutputStream.flush()
		val result = byteArrayOutputStream.toByteArray()
		byteArrayOutputStream.close()
		objectOutputStream.close()
		return result
	}
}

@Serializable
data class GetPublicKeyCredentialRequestJson(
    val allowCredentials:Array<AllowCredential>? = null,
    val challenge:String,
    val rpId:String,
    val userVerification: String,
    val timeout: Int? = null
) {
    @Serializable
    data class AllowCredential(
        val id: String,
        val transports:Array<String>,
        val type: String
    )
}

object WebAuthnUtils {
		@JvmStatic fun b64Decode(str: String?): ByteArray? {
			if(str == null) return null
			return Base64.decode(str, Base64.NO_PADDING or Base64.NO_WRAP or Base64.URL_SAFE)
		}
		@JvmStatic fun b64Encode(data: ByteArray): String {
			return Base64.encodeToString(data, Base64.NO_PADDING or Base64.NO_WRAP or Base64.URL_SAFE)
		}
		@JvmStatic fun appInfoToOrigin(info: CallingAppInfo): String {
			val cert = info.signingInfo.apkContentsSigners[0].toByteArray()
			val certHash = java.security.MessageDigest.getInstance("SHA-256").digest(cert)
			return "android:apk-key-hash:${b64Encode(certHash)}"
		}
}

const val DUMPALL = 1;
const val REPLACEALL = 2;

class MainActivity : Activity() {
	override fun onActivityResult(request: Int, errcode: Int, intent: Intent?){
		intent?.data?.also{ uri -> when (request) {
			DUMPALL -> contentResolver.openOutputStream(uri)?.bufferedWriter()?.use {
				out -> out.write(MyCredentialDataManager.loadSetJsonStr(this))
			}
			REPLACEALL -> {
				val str = String(contentResolver.openInputStream(uri)?.readAllBytes()!!);
				MyCredentialDataManager.replaceJson(this, str)
			}
		}}
		finish()
	}
	@SuppressLint("RestrictedApi")
	override fun onCreate(savedInstanceState: Bundle?) {
		super.onCreate(savedInstanceState)
		when (intent.action) {
		"uk.navediew.authlin.CREATE_PASSKEY" -> {
			val request = PendingIntentHandler.retrieveProviderCreateCredentialRequest(intent)
			if (request != null && request.callingRequest is CreatePublicKeyCredentialRequest) {
				val publicKeyRequest: CreatePublicKeyCredentialRequest = request.callingRequest as CreatePublicKeyCredentialRequest
				val jrequest = PublicKeyCredentialCreationOptions(publicKeyRequest.requestJson)
				when (jrequest.user.displayName) {
					"dumpall" -> prepareDump()
					"replaceall" -> prepareReplace()
					else -> return createPasskey(jrequest, request.callingAppInfo, publicKeyRequest.clientDataHash)
				}
				val result = Intent()
				PendingIntentHandler.setCreateCredentialException(result, CreateCredentialCancellationException())
				setResult(Activity.RESULT_OK, result)
			}
		}
		"uk.navediew.authlin.GET_PASSKEY" -> {
			val request = PendingIntentHandler.retrieveProviderGetCredentialRequest(intent)!!
			@Suppress("UNCHECKED_CAST")
			val publicKeyRequest = (request.credentialOptions as List<GetPublicKeyCredentialOption>)[0]
			val credId = WebAuthnUtils.b64Decode(intent.getBundleExtra("CREDENTIAL_DATA")!!.getString("credId"))
			val rpId = Json.decodeFromString<GetPublicKeyCredentialRequestJson>(publicKeyRequest.requestJson).rpId
			val passkey = MyCredentialDataManager.load(this, rpId, credId!!)
			val privateKey = passkey!!.keyPair!!.private as ECPrivateKey
			val uid = passkey.userHandle
			val origin = WebAuthnUtils.appInfoToOrigin(request.callingAppInfo)
			val packageName = request.callingAppInfo.packageName
			val clientDataHash = publicKeyRequest.requestData.getByteArray("androidx.credentials.BUNDLE_KEY_CLIENT_DATA_HASH")
			val jrequest = PublicKeyCredentialRequestOptions(publicKeyRequest.requestJson)
			getPasskey(
				jrequest,
				origin,
				packageName,
				uid,
				passkey.displayName,
				credId,
				privateKey,
				clientDataHash
			)
		}
		"uk.navediew.authlin.DUMP" -> prepareDump()
		"uk.navediew.authlin.REPLACE" -> prepareReplace()
		else -> {
			val textView = TextView(this)
			textView.setText("Nothing To see Here")
			textView.setTextSize(TypedValue.COMPLEX_UNIT_SP, 50.0f);
			textView.setGravity(Gravity.CENTER);
			setContentView(textView)
			//no finish(), don't do that, Text widget instead
		}}
	}

	private fun prepareReplace(){
		BiometricPrompt.Builder(this)
			.setTitle("Replace Secrets with file")
			.setSubtitle("This will DELETE ALL current secrets")
			.setAllowedAuthenticators(BiometricManager.Authenticators.BIOMETRIC_STRONG)
			.setNegativeButton("cancel", this.mainExecutor, object : DialogInterface.OnClickListener {
				override fun onClick(dialogInterface: DialogInterface, which: Int) {}
			})
			.build()
			.authenticate(
				CancellationSignal(),
				this.mainExecutor,
				object : BiometricPrompt.AuthenticationCallback() {
					override fun onAuthenticationError(errorCode: Int, errString: CharSequence) {
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
						val intent = Intent(Intent.ACTION_OPEN_DOCUMENT).apply {
							addCategory(Intent.CATEGORY_OPENABLE)
							type = "application/json"
						}
						(this@MainActivity).startActivityForResult(intent, REPLACEALL)
					}
				}
			)
	}

	private fun prepareDump(){
		BiometricPrompt.Builder(this)
			.setTitle("Dump all secrets")
			.setSubtitle("Dump to file")
			.setAllowedAuthenticators(BiometricManager.Authenticators.BIOMETRIC_STRONG)
			.setNegativeButton("cancel", this.mainExecutor, object : DialogInterface.OnClickListener {
				override fun onClick(dialogInterface: DialogInterface, which: Int) {}
			})
			.build()
			.authenticate(
				CancellationSignal(),
				this.mainExecutor,
				object : BiometricPrompt.AuthenticationCallback() {
					override fun onAuthenticationError(errorCode: Int, errString: CharSequence) {
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
						val intent = Intent(Intent.ACTION_CREATE_DOCUMENT).apply {
							addCategory(Intent.CATEGORY_OPENABLE)
							type = "application/json"
							putExtra(Intent.EXTRA_TITLE, "authlin_dump")
						}
						(this@MainActivity).startActivityForResult(intent, DUMPALL)
					}
				}
			)
	}

	@SuppressLint("RestrictedApi")
	private fun createPasskey(
		request: PublicKeyCredentialCreationOptions,
		callingAppInfo: CallingAppInfo?,
		clientDataHash: ByteArray?,
	) {
		BiometricPrompt.Builder(this)
			.setTitle("Use your screen lock")
			.setSubtitle("Create passkey for ${request.rp.name}")
			.setAllowedAuthenticators(BiometricManager.Authenticators.BIOMETRIC_STRONG)
			.setNegativeButton("cancel", this.mainExecutor, object : DialogInterface.OnClickListener {
				override fun onClick(dialogInterface: DialogInterface, which: Int) {}
			})
			.build()
			.authenticate(
				CancellationSignal(),
				this.mainExecutor,
				object : BiometricPrompt.AuthenticationCallback() {
					override fun onAuthenticationError(errorCode: Int, errString: CharSequence) {
						super.onAuthenticationError(errorCode, errString)
						finish()
					}

					override fun onAuthenticationFailed() {
						super.onAuthenticationFailed()
						finish()
					}

					override fun onAuthenticationSucceeded(result: BiometricPrompt.AuthenticationResult) {
						super.onAuthenticationSucceeded(result)

						// Generate a credentialId
						val credentialId = ByteArray(32)
						SecureRandom().nextBytes(credentialId)

						// Generate a credential key pair
						val spec = ECGenParameterSpec("secp256r1")
						val keyPairGen = KeyPairGenerator.getInstance("EC")
						keyPairGen.initialize(spec)
						val keyPair = keyPairGen.genKeyPair()

						val rpid = request.rp.id

						MyCredentialDataManager.save(this@MainActivity, MyCredentialDataManager.Credential(
							rpid = rpid,
							serviceName = request.rp.name,
							credentialId = credentialId,
							displayName = request.user.displayName,
							userHandle = request.user.id,
							keyPair = keyPair
						))
						val response = AuthenticatorAttestationResponse(
							requestOptions = request,
							credentialId = credentialId,
							credentialPublicKey = getPublicKeyFromKeyPair(keyPair), //CBOR
							origin = WebAuthnUtils.appInfoToOrigin(callingAppInfo!!),
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
						val createPublicKeyCredResponse = CreatePublicKeyCredentialResponse(credentialJson)
						val result = Intent()
						PendingIntentHandler.setCreateCredentialResponse(result, createPublicKeyCredResponse)
						setResult(Activity.RESULT_OK, result)
						finish()
					}
				}
			)
	}

	private fun populateEasyAccessorFields(json: String, rpid:String , keyPair: KeyPair, credentialId: ByteArray):String{
		val response = Json.decodeFromString<CreatePublicKeyCredentialResponseJson>(json)
		response.response.publicKeyAlgorithm = -7 // ES256
		response.response.publicKey = WebAuthnUtils.b64Encode(keyPair.public.encoded)
		response.response.authenticatorData = getAuthData(rpid, credentialId, keyPair)
		return Json.encodeToString(response)

	}
	private fun getAuthData(rpid:String, credentialRawId:ByteArray, keyPair: KeyPair ):String{
		val AAGUID = "00000000000090000000000000000000"
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
		return WebAuthnUtils.b64Encode(retVal)
	}

	@SuppressLint("RestrictedApi")
	fun getPasskey(request:PublicKeyCredentialRequestOptions, origin:String, packageName:String, uid:ByteArray, username:String, credId:ByteArray, privateKey: ECPrivateKey, clientDataHash: ByteArray?){
		BiometricPrompt.Builder(this)
			.setTitle("Use your screen lock")
			.setSubtitle("Use passkey for ${request.rpId}")
			.setAllowedAuthenticators(BiometricManager.Authenticators.BIOMETRIC_STRONG)
			.setNegativeButton("cancel", this.mainExecutor, object : DialogInterface.OnClickListener {
				override fun onClick(dialogInterface: DialogInterface, which: Int) {}
			})
			.build()
			.authenticate(
				CancellationSignal (),
				this.mainExecutor,
				object : BiometricPrompt.AuthenticationCallback() {
					override fun onAuthenticationError(errorCode: Int, errString: CharSequence) {
						super.onAuthenticationError(errorCode, errString)
						finish()
					}

					override fun onAuthenticationFailed() {
						super.onAuthenticationFailed()
						finish()
					}

					override fun onAuthenticationSucceeded(result: BiometricPrompt.AuthenticationResult) {
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
							rawId = credId, response = response, authenticatorAttachment = "platform"
						)
						val challenge = request.challenge
						val clientDataJSONb64 = WebAuthnUtils.b64Encode("{\"type\":\"webauthn.get\",\"challenge\":\"$challenge\",\"origin\":\"$origin\",\"crossOrigin\":false}".toByteArray())
						val delimiter = "response\":{"
						val credentialJson = credential.json().substringBeforeLast(delimiter) +
							delimiter + "\"clientDataJSON\":\"$clientDataJSONb64\"," +
							credential.json().substringAfterLast(delimiter)
						val result = Intent()
						val passkeyCredential = PublicKeyCredential(credentialJson)
						PendingIntentHandler.setGetCredentialResponse(result, GetCredentialResponse(passkeyCredential))
						setResult(RESULT_OK, result)
						finish()
					}
				}
			)
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
		if (keyPair==null || (keyPair.public !is ECPublicKey)) return ByteArray(0)

		val ecPoint: ECPoint = (keyPair.public as ECPublicKey).w

		// for now, only covers ES256
		if (ecPoint.affineX.bitLength() > 256 || ecPoint.affineY.bitLength() > 256) return ByteArray(0)

		// refer to RFC9052 Section 7 for details
		return "A5010203262001215820".chunked(2).map { it.toInt(16).toByte() }.toByteArray() +
			bigIntToByteArray32(ecPoint.affineX) +
			"225820".chunked(2).map { it.toInt(16).toByte() }.toByteArray() +
			bigIntToByteArray32(ecPoint.affineY)
	}

	private fun bigIntToByteArray32(bigInteger: BigInteger): ByteArray {
		var ba = bigInteger.toByteArray()
		if(ba.size < 32) {
			// append zeros in front
			ba = ByteArray(32) + ba
		}
		// get the last 32 bytes as bigint conversion sometimes put extra zeros at front
		return ba.copyOfRange(ba.size - 32, ba.size)
	}
}
