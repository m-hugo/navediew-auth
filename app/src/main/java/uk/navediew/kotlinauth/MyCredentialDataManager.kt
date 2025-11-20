package uk.navediew.kotlinauth

import android.app.Activity
import android.content.Context
import android.content.SharedPreferences
import android.util.Log
import kotlinx.serialization.Serializable
import kotlinx.serialization.encodeToString
import kotlinx.serialization.json.Json
import java.io.ByteArrayInputStream
import java.io.ByteArrayOutputStream
import java.io.ObjectInput
import java.io.ObjectInputStream
import java.io.ObjectOutputStream
import java.security.KeyPair

object MyCredentialDataManager {
    fun save(context: Context, credential: Credential){
        val credSet= loadCredSet(context)
        val keyPair:String = CredmanUtils.b64Encode(credential.keyPair!!.toByteArray())
        val cred = CredSet.SerializedCred(
            credential.rpid,
            credential.serviceName,
            credential.credentialId,
            credential.userHandle,
            credential.displayName,
            keyPair
        )
        credSet.list.add(cred)
        saveCredSet(context, credSet)
    }

    fun load(context: Context, rpid:String): MutableList<Credential> {
        val credSet = loadCredSet(context)
        val list:MutableList<Credential> = mutableListOf()
        credSet.list.forEach{
            if(it.rpid==rpid)  list.add(convertCred(it))
        }
        return list
    }
    fun loadAll(context: Context): MutableList<Credential> {
        val credSet = loadCredSet(context)
        val list:MutableList<Credential> = mutableListOf()
        credSet.list.forEach{
            list.add(convertCred(it))
        }
        return list
    }
    fun load(context: Context, rpid: String, credentialId: ByteArray):Credential?{
        val credSet= loadCredSet(context)
        credSet.list.forEach{
            if(it.rpid==rpid && it.credentialId.contentEquals(credentialId))  return convertCred(it)
        }
        return null
    }

    fun delete(context: Context, rpid: String, credentialId: ByteArray){
        val newCredSet = CredSet()
        loadCredSet(context).list.forEach{
            if(!(it.rpid==rpid && it.credentialId.contentEquals(credentialId))) {
				newCredSet.list.add(it)
            }
        }

        saveCredSet(context, newCredSet)
    }

    private fun loadCredSet(context: Context):CredSet{
        val PREF_KEY = "PREF_CREDENTIAL_SET"
        // load dataset
        val credSet:CredSet
        val sharedPref = context.getSharedPreferences(context.packageName, Activity.MODE_PRIVATE)
        val setjson = sharedPref.getString(PREF_KEY, "")?:""

        if(setjson.isEmpty()){
            credSet = CredSet()
        }else{
            credSet = Json.decodeFromString<CredSet>(setjson)
        }

        return credSet
    }

    private fun convertCred(cred:CredSet.SerializedCred):Credential{
        return Credential(
            cred.rpid,
            cred.serviceName,
            cred.credentialId,
            cred.userHandle,
            cred.displayName,
            fromByteArray(CredmanUtils.b64Decode(cred.keyPair))
        )
    }

    private fun saveCredSet(context: Context, credSet: CredSet){
        val PREF_KEY = "PREF_CREDENTIAL_SET"
        // save dataset
        val sharedPref = context.getSharedPreferences(context.packageName, Activity.MODE_PRIVATE)
        val prefsEditor: SharedPreferences.Editor = sharedPref.edit()
        val tojson = Json.encodeToString(credSet)
        prefsEditor.putString(PREF_KEY, tojson)
        prefsEditor.apply()
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
        // SerializedCred is different from Credential as KeyPair is saved in a serialized string
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
        if (byteArray == null ) return null
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

