package com.example

import java.io.BufferedInputStream
import java.security.{SecureRandom, KeyFactory}
import java.security.interfaces.{RSAPrivateKey, RSAPublicKey}
import java.security.spec.{PKCS8EncodedKeySpec, X509EncodedKeySpec}
import javax.crypto.{SecretKey, Cipher, SecretKeyFactory}
import javax.crypto.spec.{IvParameterSpec, SecretKeySpec, PBEKeySpec}

import com.nimbusds.jose._
import com.nimbusds.jose.crypto.{RSASSAVerifier, RSAEncrypter, RSASSASigner}
import com.nimbusds.jwt.{SignedJWT, JWTClaimsSet, EncryptedJWT}
import net.minidev.json.JSONArray
import spray.json.DefaultJsonProtocol
import sun.misc.{BASE64Decoder, BASE64Encoder} 

case class LeadApplicant(title: String, givenNames: String, familyName: String, nationality: String, visaType: String, passportNumber: String)
case class MainApplicant(name: String)
case class ApplicationData(visaApplicationNumber: String, inCountry: Boolean, VAC: String, emailAddress: String, leadApplicant:LeadApplicant, mainApplicant:MainApplicant)

object ApplicationDataBuilder {

  def build:ApplicationData = {
    ApplicationData(
      visaApplicationNumber = "VA1231",
      inCountry = true,
      VAC = "VAC123",
      emailAddress = "q@q.com",
      leadApplicant = LeadApplicant("Mr", "Michael", "Hicks", "GB", "visit-visa", "p123123"),
      mainApplicant = MainApplicant("John")
    )
  }
  
}

object Keys {
  
  def closing[A <: {def close() : Unit}, B](resource: A)(f: A => B): B =
    try {
      f(resource)
    } finally {
      resource.close()
    }

  def loadPublicKey(): RSAPublicKey = {
    closing(new BufferedInputStream(this.getClass.getResourceAsStream("public.key"))) { resource =>
      var key = new Array[Byte](resource.available())
      resource.read(key)
      KeyFactory.getInstance("RSA").generatePublic(new X509EncodedKeySpec(key)).asInstanceOf[RSAPublicKey]
    }
  }

  def loadPrivateKey(): RSAPrivateKey = {
    val asStream = this.getClass.getResourceAsStream("pkcs8.key")
    
    closing(new BufferedInputStream(asStream)) { resource =>
      var key = new Array[Byte](resource.available)
      resource.read(key)
      KeyFactory.getInstance("RSA").generatePrivate(new PKCS8EncodedKeySpec(key)).asInstanceOf[RSAPrivateKey]
    }
  }
}

object TokenService {

  private lazy val secureRandom = new SecureRandom
  private val EncryptionCipherTransformation = "AES/CBC/PKCS5Padding"
  private val AESBlockSize = 256
  private val AESIVSize    = AESBlockSize / 8

  private def getKeyLength: Int = 1

  val encoder = new BASE64Encoder()
  val decoder = new BASE64Decoder()

  
  def createJWT() = {
    val iv = buildIV
    val claimsSet = new JWTClaimsSet();
    claimsSet.setSubject("sub");
    claimsSet.setIssuer("IHS");
    claimsSet.setCustomClaim("ihs:iv", encoder.encode(iv))
    claimsSet.setCustomClaim("ihs:vpd", encoder.encode(encrypt(iv, "[[message to encrypt]]").getBytes("UTF-8")))
    val signedJWT = new SignedJWT(new JWSHeader(JWSAlgorithm.RS256), claimsSet)
    signedJWT.sign(getSigner)
    signedJWT.serialize()
  }

  private def getSigner = {
    val privateKey = Keys.loadPrivateKey
    val signer = new RSASSASigner(privateKey)
    signer
  }

  private def buildIV = {
    // build the initialization vector(randomly).
    val ivBytes = new Array[Byte](16)
    SecureRandom.getInstance("SHA1PRNG").nextBytes(ivBytes)
    ivBytes
  }

  def parseJWT(jwtString: String) = {
    val signedJWT = SignedJWT.parse(jwtString)
    if (signedJWT.verify(getVerifier)) {
      println("Verified...")
      val jwtClaimsSet = signedJWT.getJWTClaimsSet()
      val encodedIV = jwtClaimsSet.getCustomClaim("ihs:iv").asInstanceOf[String]
      val encodedEncryptedPayload = jwtClaimsSet.getCustomClaim("ihs:vpd").asInstanceOf[String]

      val iv = decoder.decodeBuffer(encodedIV)
      val encryptedPayload = decoder.decodeBuffer(encodedEncryptedPayload)
      val decryptedMessageAsBytes = decrypt(iv, new String(encryptedPayload))
      println("Decrypted message " + new String(decryptedMessageAsBytes, "UTF-8"))
    } else {
      println("Not verfied..")
    }
  }

  private def getVerifier = {
    val publicKey = Keys.loadPublicKey()
    val verifier = new RSASSAVerifier(publicKey)
    verifier
  }
  
  private def encrypt(iv: Array[Byte], message: String): String = {
    val cipher = Cipher.getInstance("AES/CBC/PKCS5Padding")
    cipher.init(Cipher.ENCRYPT_MODE, secretKey,new IvParameterSpec(iv))
    val cipherText = cipher.doFinal(message.getBytes("UTF-8"))
    // prepend the iv to the cipher text
    encoder.encode(cipherText)
  }

  // Decrypt a Base64-encoded string into a byte array
  def decrypt(iv:Array[Byte], message: String): Array[Byte] = {
    val cipher = Cipher.getInstance("AES/CBC/PKCS5Padding")
    val decodedMessage = decoder.decodeBuffer(message)
    cipher.init(Cipher.DECRYPT_MODE, secretKey, new IvParameterSpec(iv))
    cipher.doFinal(decodedMessage)
  }

  private lazy val secretKey: SecretKey = {
    // Random seeded salt
    val salt = new Array[Byte](8)
    secureRandom.nextBytes(salt)

    val spec = new PBEKeySpec("password".toCharArray, salt, 1024, 128);
    val factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA1")
    new SecretKeySpec(factory.generateSecret(spec).getEncoded, "AES")
  }

}
