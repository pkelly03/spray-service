package spray.examples


import com.example.{TokenService, Keys}

import scala.util.{Success, Failure}
import scala.concurrent.duration._
import akka.actor.ActorSystem
import akka.pattern.ask
import akka.event.Logging
import akka.io.IO
import spray.can.Http
import spray.client.pipelining._
import spray.util._

object SprayClient extends App {

  // we need an ActorSystem to host our application in
  implicit val system = ActorSystem("my-service-spray-client")
  import spray.examples.SprayClient.system.dispatcher // execution context for futures below
  val log = Logging(system, getClass)

  // To parse the JWS and verify it, e.g. on client-side
  log.info("Sending the message to the ihs service")

  val pipeline = sendReceive

  val responseFuture = pipeline {
    val message: String = TokenService.createJWT()
    println("Sending this message across : " + message)
    Post("http://127.0.0.1:8080/test", message)
  }

  def shutdown(): Unit = {
    IO(Http).ask(Http.CloseAll)(1.second).await
    system.shutdown()
  }

  responseFuture onComplete {
    case Success(resp) => 
      println("success: " + resp.status)
      shutdown()
    case Failure(ex) => 
      ex.printStackTrace()
      shutdown()
  }
}
