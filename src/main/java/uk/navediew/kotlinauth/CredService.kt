package uk.navediew.authlin

import android.app.PendingIntent
import android.content.Intent
import android.os.Bundle
import android.os.CancellationSignal
import android.os.OutcomeReceiver
import android.annotation.SuppressLint

import androidx.credentials.exceptions.ClearCredentialException
import androidx.credentials.exceptions.CreateCredentialUnknownException
import androidx.credentials.exceptions.GetCredentialException
import androidx.credentials.exceptions.GetCredentialUnknownException
import androidx.credentials.exceptions.GetCredentialUnsupportedException
import androidx.credentials.provider.AuthenticationAction
import androidx.credentials.provider.BeginCreatePublicKeyCredentialRequest
import androidx.credentials.provider.BeginGetCredentialResponse
import androidx.credentials.provider.BeginGetPasswordOption
import androidx.credentials.provider.BeginGetPublicKeyCredentialOption
import androidx.credentials.provider.CallingAppInfo
import androidx.credentials.provider.CreateEntry
import androidx.credentials.provider.CredentialEntry
import androidx.credentials.provider.ProviderClearCredentialStateRequest
import androidx.credentials.provider.PublicKeyCredentialEntry
import androidx.credentials.webauthn.PublicKeyCredentialRequestOptions
import androidx.credentials.provider.CredentialProviderService
import androidx.credentials.provider.BeginGetCredentialRequest
import androidx.credentials.provider.BeginCreateCredentialRequest
import androidx.credentials.provider.BeginCreateCredentialResponse
import androidx.credentials.exceptions.CreateCredentialException

class CredService: CredentialProviderService() {
	// https://developer.android.com/training/sign-in/credential-provider#handle-queries-passkey-creation
	override fun onBeginCreateCredentialRequest(
		request: BeginCreateCredentialRequest,
		cancellationSignal: CancellationSignal,
		callback: OutcomeReceiver<BeginCreateCredentialResponse, CreateCredentialException>,
	) {
		when (request) {
			is BeginCreatePublicKeyCredentialRequest -> callback.onResult(handleCreatePasskeyQuery())
			else -> callback.onError(CreateCredentialUnknownException())
		}
	}

	private fun handleCreatePasskeyQuery(): BeginCreateCredentialResponse {
		val intent = Intent("uk.navediew.authlin.CREATE_PASSKEY").setPackage(this.packageName)
		val requestCode = (1..9999).random()
		val pendingIntent = PendingIntent.getActivity(
			applicationContext, requestCode, intent,
			(PendingIntent.FLAG_MUTABLE or PendingIntent.FLAG_UPDATE_CURRENT)
		)
		val createEntries: MutableList<CreateEntry> = mutableListOf()
		createEntries.add(CreateEntry(
			"PERSONAL_ACCOUNT_ID",
			pendingIntent
		))
		return BeginCreateCredentialResponse(createEntries)
	}

	// https://developer.android.com/training/sign-in/credential-provider#handle-user-sign-in
	override fun onBeginGetCredentialRequest(
		request: BeginGetCredentialRequest,
		cancellationSignal: CancellationSignal,
		callback: OutcomeReceiver<BeginGetCredentialResponse, GetCredentialException>
	) {
		val credentialEntries: MutableList<CredentialEntry> = mutableListOf()
		for (option in request.beginGetCredentialOptions) {
			when (option) {
				is BeginGetPublicKeyCredentialOption -> credentialEntries.addAll (
					populatePasskeyData(request.callingAppInfo!!, option)
				)
				else -> return callback.onError(GetCredentialUnknownException())
			}
		}
		callback.onResult(BeginGetCredentialResponse(credentialEntries))
	}

	@SuppressLint("RestrictedApi")
	private fun populatePasskeyData(callingAppInfo: CallingAppInfo, option: BeginGetPublicKeyCredentialOption): List<CredentialEntry> {
		val passkeyEntries: MutableList<CredentialEntry> = mutableListOf()
		val request = PublicKeyCredentialRequestOptions(option.requestJson)
		val creds = MyCredentialDataManager.load(this, request.rpId)
		for (passkey in creds){
			val extra = Bundle()
			extra.putString("credId", WebAuthnUtils.b64Encode(passkey.credentialId))
			val intent = Intent("uk.navediew.authlin.GET_PASSKEY").setPackage(this.packageName)
			intent.putExtra("CREDENTIAL_DATA", extra)
			val requestCode = (1..9999).random()
			val pendingIntent = PendingIntent.getActivity(
				applicationContext, requestCode, intent,
				(PendingIntent.FLAG_MUTABLE or PendingIntent.FLAG_UPDATE_CURRENT)
			)
			passkeyEntries.add(
				PublicKeyCredentialEntry.Builder(
					context = applicationContext,
					username = passkey.displayName,
					pendingIntent,
					beginGetPublicKeyCredentialOption = option
				).build()
			)
		}
		return passkeyEntries
	}

	override fun onClearCredentialStateRequest(
		request: ProviderClearCredentialStateRequest,
		cancellationSignal: CancellationSignal,
		callback: OutcomeReceiver<Void?, ClearCredentialException>
	) {}
}
