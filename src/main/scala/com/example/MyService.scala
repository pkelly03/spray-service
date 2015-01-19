package com.example

import akka.actor.Actor
import com.nimbusds.jose.JWSObject
import com.nimbusds.jose.crypto.{RSADecrypter, RSASSAVerifier}
import com.nimbusds.jwt.EncryptedJWT
import spray.json.DefaultJsonProtocol
import spray.routing._

// we don't implement our route structure directly in the service actor because
// we want to be able to test it independently, without having to spin up an actor
class MyServiceActor extends Actor with MyService {

  def actorRefFactory = context

  def receive = runRoute(myRoute)
}

// this trait defines our service behavior independently from the service actor
trait MyService extends HttpService {

  import spray.httpx.SprayJsonSupport._

  val myRoute =
    path("test") {
        post {
          entity(as[String]) { message =>
            complete {
              TokenService.parseJWT(message)
              message
            }
          }
        }
    }
}