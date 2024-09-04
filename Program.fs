open Falco
open Falco.Routing
open Falco.HostBuilder
open Microsoft.Extensions.DependencyInjection
open Microsoft.AspNetCore.Authentication.Cookies
open Microsoft.AspNetCore.Http
open Microsoft.AspNetCore.Authentication
open System
open System.Net.Http
open System.Net.Http.Headers
open System.Threading.Tasks

/// generic oauth parse and validate logic, shared with the auth extensions package
let parseAndValidateOauthTicket =
    fun (ctx: OAuth.OAuthCreatingTicketContext) ->
        let tsk =
            task {
                let req =
                    new HttpRequestMessage(HttpMethod.Get, ctx.Options.UserInformationEndpoint)

                req.Headers.Accept.Add(MediaTypeWithQualityHeaderValue("application/json"))
                req.Headers.Authorization <- AuthenticationHeaderValue("Bearer", ctx.AccessToken)

                let! (response: HttpResponseMessage) =
                    ctx.Backchannel.SendAsync(
                        req,
                        HttpCompletionOption.ResponseHeadersRead,
                        ctx.HttpContext.RequestAborted
                    )

                response.EnsureSuccessStatusCode() |> ignore
                let! responseStream = response.Content.ReadAsStreamAsync()
                let! user = System.Text.Json.JsonSerializer.DeserializeAsync(responseStream)
                ctx.RunClaimActions user
            }

        Task.Factory.StartNew(fun () -> tsk.Result)

type OauthParams =
    { clientId: string
      clientSecret: string
      callbackPath: string }

let useGoogleOAuthService (oap: OauthParams) (jsonToClaimMap: (string * string) seq) (s: IServiceCollection) =
    let c =
        s.AddAuthentication(fun cfg ->
            cfg.DefaultScheme <- CookieAuthenticationDefaults.AuthenticationScheme
            cfg.DefaultSignInScheme <- CookieAuthenticationDefaults.AuthenticationScheme
            cfg.DefaultChallengeScheme <- "Google")

    c.AddCookie() |> ignore

    c.AddGoogle(fun opt ->
        opt.ClientId <- oap.clientId
        opt.ClientSecret <- oap.clientSecret
        opt.CallbackPath <- PathString(oap.callbackPath)
        jsonToClaimMap |> Seq.iter (fun (k, v) -> opt.ClaimActions.MapJsonKey(k, v))
        opt.ClaimActions.MapJsonSubKey("urn:google:image:url", "image", "url")
        opt.Events.OnCreatingTicket <- Func<_, _> parseAndValidateOauthTicket)
    |> ignore

    s

module Handlers =
    let home: HttpHandler = Response.ofPlainText "hello world"

    let notFound: HttpHandler =
        Response.withStatusCode 404 >> Response.ofPlainText "Nothing here"

    let secure: HttpHandler =
        Request.ifAuthenticated
            (Response.ofPlainText "Hello, Authenticated User!")
            (Response.withStatusCode 403 >> Response.ofPlainText "no")

    let challenge: HttpHandler =
        Request.ifAuthenticated
            (Response.ofPlainText "Hello, Authenticated User!")
            (Response.challengeWithRedirect "Google" "/login")

    let showCookies (context: HttpContext) =
        // printfn "%A" context.User.Claims
        context.User.Claims |> Seq.iter (printfn "%A")
        Response.ofPlainText "Wompwomp" context

let clientId = "todo"
let clientSecret = "todo"
let callbackPath = "/oauth/google/callback"

webHost [||] {
    not_found Handlers.notFound
    use_authentication
    use_authorization

    add_service (
        useGoogleOAuthService
            { clientId = clientId
              clientSecret = clientSecret
              callbackPath = callbackPath }
            []
    )

    endpoints
        [ get "/" Handlers.home
          get "/showcookies" Handlers.showCookies
          get "/login" Handlers.challenge
          get "/oauth/google/callback" Handlers.secure ]
}
