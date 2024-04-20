open Core
open Ttweetnacl.Crypto
open Printf


let encrypt key salt plaintext = 
  let nonce = Secretbox.Nonce.of_bytes @@ Bytes.of_string @@ String.pad_right ~char:'0' ~len:Secretbox.Nonce.length salt in
  let secret_key = Secretbox.Secret_key.of_bytes @@ Bytes.of_string @@ String.pad_right ~char:'0' ~len:Secretbox.Secret_key.length key in 
  Ttweetnacl.Crypto.Bytes.to_hex @@ Secretbox.box ~nonce ~secret_key ~plain_text:(Bytes.of_string plaintext)

let decrypt key salt ciphertext = 
  let nonce = Secretbox.Nonce.of_bytes @@ Bytes.of_string @@ String.pad_right ~char:'0' ~len:Secretbox.Nonce.length salt in
  let secret_key = Secretbox.Secret_key.of_bytes @@ Bytes.of_string @@ String.pad_right ~char:'0' ~len:Secretbox.Secret_key.length key in
  match (Bytes.of_hex ciphertext) with 
  | Error _ -> "garbage1"
  | Ok bt ->
      let res = Secretbox.open' ~nonce ~secret_key ~cipher_text:bt in 
      match res with 
      | None -> "garbage2"
      | Some s -> Bytes.to_string s
  

let usage = "passenc [d|e] key filename"

let processFile filename func =
  In_channel.with_file filename ~f:(fun file ->
    In_channel.iter_lines file ~f:(fun line -> printf "%s\n" (func line)))


let () =
  let sysArgs = Sys.get_argv() in 
    if (Array.length sysArgs) < 4 then
        printf "%s\n" ("Not enough arguments " ^ usage)
    else
    let iv = "0123456789012345" in
        begin
            match sysArgs.(1) with
            | "e" -> processFile sysArgs.(3) (encrypt sysArgs.(2) iv) 
            | "d" -> processFile sysArgs.(3) (decrypt sysArgs.(2) iv) 
            | _ -> printf "%s\n" usage
        end

