SRC_DIR		:=	./src
MAIN		:=	rawhttpget.py
SRCS		:=	$(wildcard $(SRC_DIR)/*.py)
TARGET_DIR	:=	.
TARGET_OBJ	:=	rawhttpget

$(TARGET_DIR)/$(TARGET_OBJ): make-target
	sudo iptables -A OUTPUT -p tcp --tcp-flags RST RST -j DROP
	ln -sf $(SRC_DIR)/$(MAIN) $(TARGET_DIR)/$(TARGET_OBJ)

.PHONY: make-target
make-target:
	$(shell mkdir -p $(TARGET_DIR))

.PHONY: test
test: $(TARGET_DIR)/$(TARGET_OBJ)
	@echo "Kicking off the test.sh script, it might take a few minutes to finish"
	@/bin/bash `pwd`/test/test.sh

.PHONY: clean
clean:
	find . \( -name "*.pyc" -or -name $(TARGET_OBJ) -or -name "*.log" \) -exec rm {} \;
