extends Node2D


var totalenemies = 0
var rng = RandomNumberGenerator.new()
var enemies_left = 0


func _process(delta):
	var mousepos = get_global_mouse_position()
	get_node("Crosshair").position = mousepos

	if enemies_left == 0:
		rng.seed = Vals.hits ^ enemies_left ^ Vals.playerdmg
		var fbytes = rng.randf()
		Vals.sd = fbytes
		get_tree().change_scene("res://Scenes/Level_2.tscn")

func _on_Enemy_killed():
	enemies_left -= 1

func _on_Enemy_alive():
	totalenemies += 1
	#enemies_left += 1

func _ready():

	Input.set_mouse_mode(Input.MOUSE_MODE_HIDDEN)


