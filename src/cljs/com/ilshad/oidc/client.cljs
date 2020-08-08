(ns com.ilshad.oidc.client
  "OpenID Connect Client"
  (:require [clojure.string :as string]
            [cljs.tools.reader.edn :as edn]
            [goog.crypt.base64 :as base64]
            [goog.events :as events])
  (:import [goog.events EventType]
           [goog.net XhrIo]))

(defonce state (atom {}))

(declare run)

(defn- json-response [event]
  (js->clj (.. event -target getResponseJson) :keywordize-keys true))

(defn- json-request [data]
  (.stringify js/JSON (clj->js data)))

(defn- request* [{:keys [url method body headers success error]}]
  (doto (XhrIo.)
    (events/listen goog.net.EventType.SUCCESS success)
    (events/listen goog.net.EventType.ERROR error)
    (.send url method body headers)))

(defn- request
  [{:keys [url method data success error]
    :or {error identity method "GET"}}]
  (request* {:url     url
             :method  method
             :body    (some-> data json-request)
             :success (comp success json-response)
             :error   error
             :headers (when (= method "POST")
                        (clj->js {"Content-Type" "application/json"}))}))

(defn- request-get [url k]
  (request {:url url
            :success (fn [data]
                       (swap! state assoc k data)
                       (run))}))

(defn- request-post [url data k]
  (request {:url url
            :method "POST"
            :data data
            :success (fn [response]
                       (swap! state assoc k response)
                       (run))}))

(def LOCAL-STORAGE-KEY "sim.oidc")

(defn- load-local []
  (reset! state (edn/read-string (.getItem js/localStorage LOCAL-STORAGE-KEY))))

(defn- save-local []
  (.setItem js/localStorage LOCAL-STORAGE-KEY (pr-str @state)))

(defn- encode-uri [s] (js/encodeURIComponent s))

(defn- login-url []
  (str (-> @state :conf :authorization_endpoint)
       "?scope=openid"
       "&client_id="     (-> @state :regs :client_id)
       "&response_type=" (-> @state :regs :response_types first encode-uri)
       "&redirect_uri="  (-> @state :regs :redirect_uris first encode-uri)
       "&nonce="         (str (random-uuid))
       "&state="         (str (random-uuid))
       "&display=page"))

(defn- redirect []
  (save-local)
  (set! (.-location js/window) (login-url)))

(defn- conf-url [] (-> @state :url (str "/.well-known/openid-configuration")))
(defn- jwks-url [] (-> @state :conf :jwks_uri))
(defn- regs-url [] (-> @state :conf :registration_endpoint))

(defn- regs-params []
  {:grant_types    [:implicit]
   :issuer         (-> @state :conf :issuer)
   :redirect_uris  ["http://localhost:9999/me"]
   :response_types ["id_token token"]
   :scope          "openid profile"})

(defn- run []
  (condp #(empty? (get (deref %2) %1)) state
    :conf (request-get (conf-url) :conf)
    :jwks (request-get (jwks-url) :jwks)
    :regs (request-post (regs-url) (regs-params) :regs)
    (redirect)))

(defn- clear-location-hash []
  (.replaceState js/history nil nil " "))

(defn- read-token-partition [string]
  (js->clj (.parse js/JSON (base64/decodeString string))
           :keywordize-keys true))

(defn- read-token [string]
  (let [[header payload signature] (string/split string #"\.")]
    {:header    (read-token-partition header)
     :payload   (read-token-partition payload)
     :signature signature}))

(defn- read-query-string [s]
  (into {}
    (for [i (string/split s #"&")]
      (let [[k v] (string/split i #"=")]
        [(keyword k) v]))))

(defn- parse-authentication-response []
  (let [s (-> js/window .-location .-hash (subs 1))]
    (when-not (empty? s)
      (let [response (read-query-string s)]
        {:response      response
         :access-token (-> response :access_token read-token)
         :id-token     (-> response :id_token read-token)}))))

(defn- authenticated-from-response []
  (when-let [data (parse-authentication-response)]
    (swap! state assoc :authentication data)
    (save-local)
    (clear-location-hash)
    data))

(defn- authenticated-from-local []
  (load-local)
  (:authentication @state))

;;
;; Public API
;;

(defn authenticate [url]
  (swap! state assoc :url url)
  (run))

(defn authenticated? []
  (or (authenticated-from-response)
      (authenticated-from-local)))
