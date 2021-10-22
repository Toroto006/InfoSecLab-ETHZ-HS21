LEGI_NR:=18-951-566
SUB_FILES:= Sigma/sigma.py TLS/tls_crypto.py TLS/tls_handshake.py TLS/tls_psk_handshake.py TLS/tls_psk_state_machines.py

submission: $(SUB_FILES)
	mkdir zip_make_folder
	@for f in $(SUB_FILES); do mv $${f} zip_make_folder/; done
	zip "module_2_submission_$(LEGI_NR).zip" zip_make_folder/*
	rmdir -f zip_make_folder
