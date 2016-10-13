[CCode (cheader_filename = "stdio.h,jwt.h")]
namespace JWT {
	[CCode (cname = "jwt_alg_t", cprefix = "JWT_ALG_", has_type_id = false)]
	public enum Jwt_alg {
		NONE,
		HS256,
		HS384,
		HS512
	}

	[Compact]
	[CCode (cname = "struct jwt", cprefix = "jwt_", free_function = "jwt_free")]
	public class Jwt {
		[CCode (cname = "jwt_make")]
		public Jwt ();

		[CCode (cname = "jwt_dup")]
		public Jwt dup ();

		public int decode(string token, uint8* key, int key_len);

		public string? get_grant(string grant);
		public int add_grant(string grant, string val);
		public int del_grant(string grant);
		public int add_grants_json(string json);

		public int dump_fp(out GLib.FileStream fp, int pretty);
		public string? dump_str(int pretty);

		public int encode_fp(out GLib.FileStream fp);
		public string? encode_str();

		public int set_alg(Jwt_alg alg, string key, int len);
		public Jwt_alg get_alg();
	}
}
