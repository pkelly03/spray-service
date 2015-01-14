package spray.examples

import java.io.BufferedInputStream
import java.security.spec.{PKCS8EncodedKeySpec, X509EncodedKeySpec}
import java.security.{KeyFactory, KeyPairGenerator}
import java.security.interfaces.{RSAPrivateKey, RSAPublicKey}

import com.example.MyServiceJsonProtocol._
import com.nimbusds.jose.{Payload, JWSAlgorithm, JWSHeader, JWSObject}
import com.nimbusds.jose.crypto.{RSASSAVerifier, RSASSASigner}

import scala.util.{Success, Failure}
import scala.concurrent.duration._
import akka.actor.ActorSystem
import akka.pattern.ask
import akka.event.Logging
import akka.io.IO
import spray.json.{JsonFormat, DefaultJsonProtocol}
import spray.can.Http
import spray.httpx.SprayJsonSupport
import spray.client.pipelining._
import spray.util._

case class Message(id: String, content: String)

object MyServiceJsonProtocol extends DefaultJsonProtocol {
  implicit val messageFormat = jsonFormat2(Message)
}

object SprayClient extends App {

  /*

  Generate public private keys so scala could read them

  ssh-keygen new rsa key
  openssl pkcs8 -topk8 -inform PEM -outform DER -in demo.rsa  -nocrypt > pkcs8_key
  openssl rsa -in demo.rsa -pubout -outform DER -out public_key.der

   */

  def loadPublicKey() : RSAPublicKey = {
    val stream : BufferedInputStream = new BufferedInputStream(this.getClass().getResourceAsStream("/com/example/public_key"))
    var key = new Array[Byte](stream.available())
    stream.read(key)
    KeyFactory.getInstance("RSA").generatePublic(new X509EncodedKeySpec(key)).asInstanceOf[RSAPublicKey]
  }

  def loadPrivateKey() : RSAPrivateKey = {
    val stream : BufferedInputStream = new BufferedInputStream(this.getClass().getResourceAsStream("/com/example/pkcs8_key"))
    var key = new Array[Byte](stream.available())
    stream.read(key)
    KeyFactory.getInstance("RSA").generatePrivate(new PKCS8EncodedKeySpec(key)).asInstanceOf[RSAPrivateKey]
  }

  // we need an ActorSystem to host our application in
  implicit val system = ActorSystem("my-service-spray-client")
  import system.dispatcher // execution context for futures below
  val log = Logging(system, getClass)
  val keyGenerator = KeyPairGenerator.getInstance("RSA")
  keyGenerator.initialize(1024)
  val keyPair = keyGenerator.generateKeyPair()

  val publicKey = loadPublicKey()
  val privateKey = loadPrivateKey()

  val signer = new RSASSASigner(privateKey)

  // Prepare JWS object with simple string as payload
  var jwsObject = new JWSObject(new JWSHeader(JWSAlgorithm.RS256), new Payload("In RSA we trust!"))

  // Compute the RSA signature
  jwsObject.sign(signer)

  // To serialize to compact form, produces something like
  // eyJhbGciOiJSUzI1NiJ9.SW4gUlNBIHdlIHRydXN0IQ.IRMQENi4nJyp4er2L
  // mZq3ivwoAjqa1uUkSBKFIX7ATndFF5ivnt-m8uApHO4kfIFOrW7w2Ezmlg3Qd
  // maXlS9DhN0nUk_hGI3amEjkKd0BWYCB8vfUbUv0XGjQip78AI4z1PrFRNidm7
  // -jPDm5Iq0SZnjKjCNS5Q15fokXZc8u0A
  val s = jwsObject.serialize()

  println("S : " + s)

  // To parse the JWS and verify it, e.g. on client-side
  jwsObject = JWSObject.parse(s)

  val verifier = new RSASSAVerifier(publicKey)
  println("VERIFIED : " + jwsObject.verify(verifier))

  log.info("Requesting the message from ihs service")

  import MyServiceJsonProtocol._
  import SprayJsonSupport._
  val pipeline = sendReceive ~> unmarshal[Message]

  val responseFuture = pipeline {
    Get("http://127.0.0.1:8080/test")
  }
  responseFuture onComplete {
    case Success(Message(_, content)) =>
      log.info("Contents of message {}", content)
      shutdown()

    case Failure(error) =>
      log.error(error, "Couldn't get message")
      shutdown()
  }

  def shutdown(): Unit = {
    IO(Http).ask(Http.CloseAll)(1.second).await
    system.shutdown()
  }
}
